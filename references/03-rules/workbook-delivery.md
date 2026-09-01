# Analyst Workbook Delivery Contract

## Contents

- Delivery authority and repair
- Workbook structure
- Wording and layout
- Verification and completion

## Authority And Repair

Build one analyst-facing workbook directly from the sealed canonical record. The
canonical JSON and manifest remain the lossless technical and recovery artifacts.
Do not create a second technical workbook. Operations and audit decisions are
different entities: each operation owns one Recommendations row, while each audit
decision owns exactly one primary row under the precedence below. Cross-references
may point to an owner row but may not create a second decision surface.

The deterministic mapper assigns each record to one owning sheet and one primary
row. Links may point to that row; copied prose may not form another decision
surface. Before editorial work, every canonical record must contain current
configured behaviour, decision class, consequence or benefit, preserved
distinctions, target direction, confidence, evidence boundary when applicable,
and next step.

If one of those fields is missing or wrong, stop. Start a semantic-successor
package from the same locked source, bound to the predecessor canonical seal and
an approved field-level repair brief, then rerun the complete audit workflow. The
mapper, editor, and builder may not infer, patch, or overwrite it.

The fresh editorial context may edit only declared prose fields. It must preserve
IDs, object keys and names, event/parameter/destination identifiers, decision
class, priority, confidence, evidence boundary, target direction, operation
content, dependencies, static verification, and rollback.

## Workbook Structure

All workbooks contain:

| Sheet | Purpose |
| --- | --- |
| `01 Overview` | Source/static boundary, status, counts, highest-value actions, target summary, retained architecture, blockers, source-to-target object-count and operation summary, and one next step |
| `02 Recommendations` | Every decision-ready atomic operation exactly once |
| `03 Decisions Needed` | Every owner-decision audit record exactly once, with recommendation and what it unlocks |
| `04 Full Audit` | Every audit decision not owned by Decisions Needed or Custom Code, including retained and not-applicable outcomes |
| `05 Custom Code` | Every applicable code audit decision not already owned by Decisions Needed; omit when none applies |

Primary audit-decision ownership is deterministic: `03 Decisions Needed` first,
then `05 Custom Code`, then `04 Full Audit`. The union of those three sheets must
equal the canonical audit-decision set and the sets must be pairwise disjoint.
`02 Recommendations` remains a separate operation surface and links back to the
owning audit decision through exact IDs.

`02 Recommendations` has exactly eight visible columns:

1. `Action + operation ID`
2. `Finding type + priority`
3. `Affected scope`
4. `Current setup`
5. `Why it matters`
6. `Recommended target`
7. `Analyst decision / implementation handoff`
8. `Static verification / rollback`

Long field paths, hashes, redacted payload detail, and dependencies belong in
row-bound comments and canonical JSON. Comments must never expose secret or
personal values; preserve the exact action through its canonical hash and keep
the unredacted source only in the sealed technical record. The visible row names
actual GTM objects and the complete change in analyst language.

`03 Decisions Needed` uses `Decision ID`, `Question`, `Why this is needed`,
`Recommendation`, `Affected scope`, and `What the answer unlocks`.
`04 Full Audit` uses `Audit ID`, `Area`, `Affected scope`, `Decision`,
`Plain-language finding`, `Outcome / linked action`, `Priority`, and
`Evidence confidence`. The Area cell also names the human-readable audit focus,
so multiple obligations in one area cannot look contradictory or duplicated.

## Wording And Layout

Use the controlled human labels:

| Canonical class | Visible label |
| --- | --- |
| `defect` | Needs correction |
| `correct_but_materially_non_optimal` | Optimisation |
| `justified_as_is` | Appropriate as configured |
| `owner_decision` | Decision needed |
| `container_evidence_limit` | Cannot determine from container evidence |
| `not_applicable` | Not applicable |

Lead with the current configured situation, then the concrete consequence or
benefit, target, preserved behaviour, and next step. Describe an optimisation as
simplification or drift reduction, not as a disguised defect. For retained work,
name the exact positive distinction. For decisions and limits, state the one
missing answer or proof and the responsible next step.

Visible prose must not expose internal workflow vocabulary such as semantic
obligation, scan candidate, clean-room, seal, reconciliation class, context ID,
validator, parser trace, or source hash. Never use vague instructions such as
“review configuration”, “optimise tag”, or “fix consent”. Do not invent scores,
savings, implementation time, runtime behaviour, vendor receipt, or legal claims.

Use the requested language, default English. Localisation changes headings and
prose only, never identifiers. Use textual status labels plus accessible colours,
filters, frozen headers, wrapped top-aligned cells, stable widths, outline groups,
and a clear section-navigation row that points readers to the workbook tabs. Do
not merge data cells, clip content, truncate silently, or use colour as the only
carrier of meaning.

## Verification And Completion

The delivery mapper first independently reconstructs the canonical record and
requires the exact closed delivery-map projection and seal. The deterministic
builder must verify exact primary ownership and row coverage,
locked-field equality, navigation text, absence of unexpected formulas or
renderer artifacts, imported comment text/location/count, redaction,
source/record hashes, and safe cell values.
Rebuild from only that reconstructed canonical authority, its manifest, and the
sealed editorial artifact;
the normalized sheet/cell/navigation/comment/dimension model must match.

Then run two host-scoped checks with separate allowlisted inputs:

- fidelity compares every visible row with its bound canonical record and rejects
  changed meaning, omitted caveats, overstated consequences, mismatched actions,
  or altered identifiers;
- workbook-only reader review receives the workbook, audience brief, and rendered
  previews only, and rejects unclear, non-standalone, repetitive, machine-oriented,
  illegible, or poorly navigable output.

The editorial pass, fidelity reviewer, and workbook-only reader each require a
workflow-globally unused reasoning-context ID. Fidelity and reader also require
workflow-globally unused host-receipt IDs. Check them against source checkpoints,
source audits and history, every neutral and projection review, prior editorial
versions, and prior workbook builds—not merely against the other delivery checks.

Apply presentation-only corrections through a new editorial artifact and rebuild.
Start a semantic successor only for a canonical completeness or fidelity defect. Render and
inspect every visible sheet, then pass formula-injection and privacy checks before
sealing delivery. Workbook completion is not GTM mutation approval.

The automated privacy check is deliberately bounded. It covers configured
sensitive-key indicators, email-like values, local user paths, secret/token-like
assignments, workbook comment redaction, and formula-injection safety. A pass does
not certify the absence of every possible form of personal data. Preserve the
separate semantic audit of identity and privacy-sensitive fields and do not turn
the delivery check into a generic DLP system.
