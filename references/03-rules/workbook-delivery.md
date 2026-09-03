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
surface. Before editorial work, every canonical record must contain the evidence
and fields required by its decision class. Recommendations require current
behaviour, consequence or benefit, preserved distinctions, exact target and next
step. Owner decisions require their question and next step; evidence limits
require their boundary and next step. Retained and not-applicable decisions use
their criteria assessment and the class's existing no-change meaning. Do not
require optional recommendation fields from these compact classes or invent
targets to fill their workbook cells. The mapper must preserve evidence limits
in visible findings and obtain summaries from the populated class-specific fields.

If one of those fields is missing or wrong, stop delivery. Use the focused repair
procedure in `workflow-and-assurance.md` with user-authorized exact decision IDs
and a concrete reason. The helper creates a new working successor retaining
validated source evidence, checkpoints, both audits, seals, and histories, while
excluding generated downstream outputs. The predecessor remains unchanged.
Repair the exact owning stage. Amend source records through the existing protocol
only when their own judgments are defective; a reconciliation-only error keeps
both source audits and seals unchanged. Then reconstruct reconciliation, target
validation, canonical authority, and the dependent workbook checks. Do not restart
the full source audits. The mapper,
editor, builder, and repair helper may not invent or patch sealed semantics.

The editorial transformation may edit only declared prose fields. It must preserve
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

All detail sheets have a filterable `Audit area` column immediately after their
identifier/action column. It groups existing audit classifications into upper-level
change categories; it does not create new obligations or alter judgments.
Use the same labels across sheets. The mapper proposes a category from
`AUDIT_AREA_CATEGORIES`, with fact-specific naming/folder distinctions. An
operation spanning areas initially uses its highest-priority source decision
(stable decision ID breaks ties); all source area IDs remain in its note.
During the existing editorial step, choose one label from `AUDIT_AREA_LABELS`
according to the issue addressed by the established finding, not merely the
object's implementation type. For example, consent handling implemented in custom
code belongs under CMP & consent; removal of duplicated loader code belongs under
Duplicates & consolidation. A category is a navigation label, not a new verdict.
The existing fidelity review checks that it faithfully describes the finding.
Do not duplicate an operation to put it in multiple categories. Full Audit keeps
the precise original area and focus in a separate `Detailed audit focus` column.
Naming findings about code objects remain `Naming`, not `Custom code & templates`.

`02 Recommendations` has exactly nine visible columns:

1. `Action + operation ID`
2. `Audit area`
3. `Finding type + priority`
4. `Affected scope`
5. `Current setup`
6. `Why it matters`
7. `Recommended target`
8. `Analyst decision / implementation handoff`
9. `Static verification / rollback`

Long field paths, hashes, redacted payload detail, and dependencies belong in
row-bound comments and canonical JSON. Comments must never expose secret or
personal values; preserve the exact action through its canonical hash and keep
the unredacted source only in the sealed technical record. The visible row names
actual GTM objects and the complete change in analyst language.

Keep visible affected-scope summaries compact: name at most three representative
objects, then state how many additional objects are covered. Put the complete,
exact object-key inventory in that row's note so readability never weakens
traceability.
For Recommendations, derive that scope from the owning decisions and the complete
declared operation: changed, removed, renamed, paused, deleted and created objects,
plus remap sources, destinations and explicit consumers. An audit's subject alone
is not the complete scope of a multi-object recommendation.

`03 Decisions Needed` uses `Decision ID`, `Audit area`, `Priority`, `Question`, `Why this is needed`,
`Recommendation`, `Affected scope`, and `What the answer unlocks`.
`04 Full Audit` uses `Audit ID`, `Audit area`, `Detailed audit focus`, `Affected scope`, `Decision`,
`Plain-language finding`, `Outcome / linked action`, `Priority`, and
`Evidence confidence`. The Detailed audit focus cell also names the human-readable focus,
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

Every row must be understandable on its own. Tie its prose to the named object,
object group, event, vendor, route, or configuration at issue. Do not repeat
generic stock paragraphs across unrelated rows. Keep object inventories out of
visible prose when the affected-scope cell and row note already carry them.

Keep Current behavior limited to the source configuration. Describe pending
repairs in the finding or target using explicit proposed-change wording. Convert
audit-author instructions into the actual finding and its existing linked action.
The Full Audit display focus is editable prose; its underlying area, fact kind
and audit mechanism remain locked for traceability.
When a row assesses naming or another non-behavioural property of a code object,
label that assessment explicitly instead of inventing executable behaviour.
Explain shared conventions once in the overview; keep each row object-specific.
When a retained finding depends on a separately listed change or owner answer,
name the exact existing operation or decision ID and its destination sheet.
Clarify that no additional change is needed for this audit focus, rather than
implying the object needs no change at all. Never invent a cross-reference.

In `01 Overview`, present highest-value actions as a numbered, one-action-per-line
list. Allocate enough visible rows for every summary block and verify that no
action or summary is clipped in the rendered preview.

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

Then run two checks with separate fresh agents and locked inputs:

- fidelity compares every visible row with its bound canonical record and rejects
  changed meaning, omitted caveats, overstated consequences, mismatched actions,
  or altered identifiers;
- workbook-only reader review receives the workbook, audience brief, and rendered
  previews only, and rejects unclear, non-standalone, repetitive, machine-oriented,
  illegible, or poorly navigable output.

The fidelity reviewer and workbook-only reader use distinct agent/context labels
and receive only their declared inputs; neither receives the other's findings.
Record each locked input and output hash.

Apply presentation-only corrections through a new editorial artifact and rebuild.
Use a focused working successor for a canonical completeness or semantic fidelity
defect. Copying retained evidence does not author judgments or establish their
validity against a new scan. Render and inspect every visible sheet, then pass
formula-injection and privacy checks before
sealing delivery. Workbook completion is not GTM mutation approval.

The automated privacy check is deliberately bounded. It covers configured
sensitive-key indicators, GTM parameter and name/value-table payloads, email-like
values, local user paths, secret/token-like assignments, workbook comment
redaction, and formula-injection safety. Parameter names, object identities, and
canonical action hashes remain available; matched sensitive values stay in the
sealed technical evidence, not workbook comments. A pass does not certify the
absence of every possible form of personal data. Preserve the
separate semantic audit of identity and privacy-sensitive fields and do not turn
the delivery check into a generic DLP system.
