# Verified Dual-Audit Workflow

## Contents

- Authority and stage boundary
- Stages 1–7
- Independence, repair, and target-validation rules
- Speed and trust

## Authority And Boundary

The workflow authority is the sealed canonical JSON record. The analyst workbook
is a faithful decision surface, not an executable approval packet. This version
ends after one validated workbook. It does not mutate GTM, generate or apply an
import, create a GTM version, publish, certify readback, create a change log, or
compare completed audits.

The fixed workflow is:

```text
locked source/context/contract
  -> canonical deterministic scan
  -> raw-source assurance in a separate fresh agent context
  -> typed obligation ledger
  -> two complete parallel audits in separate fresh agent contexts
  -> independent validation and seals
  -> fresh-agent reconciliation and neutral review
  -> exact target operations
  -> deterministic validation of the combined target
  -> sealed canonical record
  -> evidence-locked editorial transformation
  -> one workbook plus technical/fidelity/reader/privacy gates
```

There is no three-run mode, reduced-depth mode, same-context fallback, or legacy
workbook path.

One normal execution has one comprehensive source pass: scan and assurance,
two independent audits in parallel, and one reconciliation. Simulation after
reconciliation validates the combined packet without new semantic reviews or
recommendations. Separately authorized development evaluations may repeat to
improve the skill; they are outside this product workflow.

## Stage 1 — Evidence Gate

Accept one complete unambiguous ContainerVersion export or equivalent read-only
evidence. Lock source, context, skill identity, audit contract, vendor/template
registry, and optional approved requirement identities. Block partial identity,
invalid entity layers, duplicate IDs, or missing evidence that prevents a static
configuration judgment.

The user must explicitly supply or identify exactly one authoritative source.
Never search for a likely export, infer a filename, or choose between supplied
files. Use the exact missing-source request and successful-completion wording
in `SKILL.md`; all other necessary clarification remains contextual. Once the
selected source resolves and its complete identity passes, proceed without a
redundant confirmation.

## Stage 2 — Canonical Scan And Independent Assurance

Run every scan clause once and produce coordinate-bound facts for objects,
configured leaves and branches, references, consumers, terminal sources,
effective settings, firing/blocking topology, custom-code segments, consent,
routes, destinations, families, relationship candidates, and applicability.

Run the assurance path in a separate fresh agent context over the locked raw JSON,
assurance rules, and canonical scan identity. It receives no semantic findings
and recomputes, without calling the scanner's corresponding derived logic:

- source hash, layers, IDs, and object identity;
- reference endpoints, consumers, and recursive variable sources;
- trigger/event/blocker identities, including paired Custom Event operands;
- Google tag and `gtagConfig` setting ownership, direct fields, effective values,
  and same-destination value comparisons;
- destination and host identities, including route-specific variable chains and
  a negative guard against unrelated URL references;
- configured leaf, branch, recursive trace, and peer identities that own work;
- code objects, executable segments, line ranges, hashes, and parser status;
- matched/unmatched vendor identities and one canonical research owner;
- relationship candidate identity, members, type, coordinates, and owner; and
- exact 27-area coverage membership plus raw-evidence applicability for
  ecommerce, sensitive data, source-to-destination value semantics, and
  portability.

Record the assurance agent/context labels plus exact locked input and output
hashes. Any mismatch blocks semantic review. A mechanism may be inapplicable only with a
source-counted zero; it is never silently skipped. Assurance is intentionally a
critical-invariant recomputation, not a second full scanner.

Obligation construction preserves the assured applicability result. Domain
routing for a configuration obligation is derived only from the raw source facts
named by its evidence anchors; registry-enriched statements and contract metadata
are never an applicability source.

Area ownership is explicit: area 1 is the evidence and assurance gate, areas
2–26 are complete semantic-audit obligations, and area 27 is the exact-operation
and deterministic target-validation control. Gate/control outcomes do not receive
invented semantic decision classes.

## Stages 3 And 4 — Two Complete Independent Audits

Audit A starts from the assured literal inventory and chains, then closes
transversal candidates, families, relationships, tag-control topology, custom
code, shared infrastructure, and the container target. Audit B starts from
destination, consent/routing ownership, families, and the greenfield target,
then closes the same transversal units. Both complete every applicable semantic
obligation in areas 2–26 using the same decision schema. Literal object and
branch completeness is proven once by the scan assurance and compact checkpoint,
not restated as repetitive per-object prose.

Find consequential cleanup and a coherent complete target during these initial
audits. Follow every proposed consolidation or removal through all consumers and
remaining dependencies. Close shared settings, trigger/blocker ownership,
loader/destination families, custom-code behaviour, and final naming before
sealing. Generated candidates are neutral prompts, not verdicts or limits on
source-based discovery; preserve justified variants and true owner decisions.

Before sealing, check references to proposed operations in decision prose,
discovery decisions, operation explanations and global conclusions against the
audit's complete final operation set. After consolidating operations, update an
affected reference to the surviving operation only when its scope supports the
claim; otherwise correct the owning assessment. Distinguish proposed-operation
references from source names and historical quotations. This source-local closure
preserves peer independence; reconciliation still checks the combined selected set.

Give each necessary create, write, remap or deletion one operation owner across
the complete audit. When several obligations expose a shared target, use
meaningful, disjoint action sets and existing `depends_on` links: for example,
creation of a shared settings owner and adoption by its consumers, or consumer
remapping followed by retirement. Each finding describes its own contribution,
dependencies, verification and rollback while preserving the complete combined
target. Check the whole operation set before application. Repeating the complete
action packet under different IDs is not separate ownership; neither filler
actions nor downgraded findings resolve an ownership conflict.

An absent authored operation is unfinished agent work. It does not turn a known
static repair into an external owner decision. Separate independently actionable
defects from unrelated ownership questions within the same object or family;
use existing atomic decisions and structured open discovery when needed. Do not
guess missing defaults or guard values. Source-visible missing guards or global
resets establish configured behaviour, not proof of a runtime failure.

The decision schema is class-specific. All decisions carry a concise criteria
assessment, priority, confidence, and citations. Exact target, verification,
rollback, and operation fields are mandatory for actionable recommendations;
owner questions and evidence boundaries are mandatory only for their respective
classes. Appropriate-as-configured and not-applicable decisions stay compact.

Before approved external requirements are released, each audit seals a
source-only checkpoint. Audit B is also generated-candidate-blind until its
checkpoint. Later released candidates and requirements may add work, but cannot
rewrite checkpointed discovery.

Before reconciliation:

- each audit receives a separate locked input bundle and runs in a separate fresh
  agent context;
- both may read the same version-locked shared skill rules without sharing
  judgments;
- neither receives the other's verdicts, scratch, discoveries, rationales, or
  target proposals until both are complete and sealed;
- the orchestrator coordinates but authors neither result;
- sharding keeps each implementation family complete and partitions transversal
  shared-infrastructure obligations by audit area into bounded deterministic
  units; no obligation is split or omitted;
- workload counts and the sharding decision are deterministically reconstructed
  from the locked scan, assurance, and audit before merge and again at final
  validation;
- each fresh agent authors one isolated declarative plan. Locked neutral
  candidate groups enumerate exact obligation IDs; compact decision profiles
  assign whole candidates, while exact obligation overrides split candidates.
  A profile may share one decision only when
  its criteria assessment, target, preserved distinctions, next step, and
  evidence meaning are genuinely identical. Each actionable operation resolves
  to one obligation because its operation and target are unique. Case-sensitive
  vocabulary and complete actionable operation proposals come from the locked
  authoring contract. Runtime
  uncertainty bounds runtime claims but does not defer a static verdict.
  The maintained applicator validates the whole plan before writing and
  deterministically merges declared work units;
- manifests, records, units, decisions, discoveries, proposals, and structured
  action rows use recursively closed declared schemas; unknown or malformed
  nested authoring context blocks before merge;
- each audit performs global closure over shared configuration, consent, routing,
  destinations, identity, and architecture; and
- each complete audit is coverage-validated and immutably sealed with lightweight
  provenance: agent/context labels, locked input hash, and sealed output hash.

The artifact validator proves bundle integrity, distinct Audit A/B labels,
coverage, and seals. Labels identify workflow owners; they are not security
credentials. If the AI environment cannot create the two required fresh agent
contexts, block with a concise capability message. An amendment uses a fresh
agent context bound to the prior seal and archives the previous
artifact and seal in append-only history.
Its audit artifact cites the current prior audit-seal hash while retaining the
immutable source checkpoint and bundle identity. A
maintained plan application projects the explicit amendment parent and fresh
agent/context labels after validating them before writes; generated audit JSON
is not a manual provenance-editing surface. A
seal also binds an exact immutable snapshot of the work-unit manifest and every
completed family-shard file used for that audit version. Current and historical
audits are always revalidated against their own sequence-addressed snapshots, so
later amendment edits cannot alter predecessor evidence. Missing, changed,
duplicated, or orphan snapshot identities block the complete chain. Unit identity
is independently recomputed from explicit immutable audit, source, ledger,
family, and membership fields. Snapshot roots and contents must be regular,
self-contained paths below the seal directory; symlinks, junctions, reparse
points, and resolved path escapes block before any evidence is read. Reconstruct
the exact sorted decisions and ordered discoveries from all declared units and
compare that result directly with the candidate or sealed audit; hashes stored in
the audit are supporting evidence, never the derivation proof. A
closed manifest, record, and work-unit schema rejects undeclared context before
merge or sealing. The nested decision, discovery, and completed-unit lists reject
non-object and duplicate rows, and the complete proof must equal one exact
reconstructed object. Seal, history, snapshot, bundle, and canonical-audit roots
must remain direct regular children of the package; no ancestor junction may
redirect reads or writes. The package root itself must also be a regular directory
name, not a symlink, junction, or reparse point. Before every public workflow
read or write, enumerate the complete package tree without following redirects;
any redirected descendant blocks the command before it can use package evidence
or create output. Every manifest-carried file, build, workbook, editorial,
work-unit, or locked-review path must additionally be one non-blank canonical
forward-slash relative path with no absolute prefix, drive, empty component,
`.` component, `..` component, or alternate-data-stream separator. Rehashing a
manifest never authorises a path outside its owning package directory. A
failed amendment leaves current and historical seals unchanged. Canonical sealing
closes in-place source amendments for that package. Later semantic repair uses a
new working successor retaining validated source evidence and both audit histories;
the same amendment protocol applies there after downstream outputs are excluded.
Stage the new audit, new seal, immutable work-unit snapshot, and predecessor
history together. A failed commit must restore the prior current audit and seal
byte-for-byte, remove the new snapshot and partial history, and clear staging.
Every later sealed-audit gate revalidates the complete contiguous parent chain
and every archived audit, checkpoint, release binding, and versioned
work-unit snapshot; missing history is a blocker.
Restore only a target that the commit actually replaced, and only from a complete
hash-verified backup. If restoration itself cannot finish, retain the recovery
staging evidence and block all downstream work.
Before staging any amendment, revalidate the complete existing owner chain and
the coverage release's exact current-checkpoint binding. Candidate validity never
authorises a write over stale predecessor provenance.

Audit A and Audit B use distinct agent/context labels and remain mutually blind
until completion. Other peer reviews use distinct labels within the review pair.
Every stage records its locked input and sealed output hashes so provenance is
checkable. Distinct labels are required only where peers must be independent.

## Stage 5 — Reconciliation And Neutral Verification

Compare atomic decisions by obligation, exact subject set, family, relationship,
and target. Classify agreement, compatible complementary conclusions, one-sided
finding, conflicting verdict, conflicting target, or different evidence boundary.
Do not vote, average, silently prefer an audit, or merge unmatched claims without
verification.

A separate fresh reconciliation agent is mandatory after both audits are sealed.
Only identical complete canonical semantic payloads may bypass neutral review.
Matching verdict labels, empty optional targets or equal action fields do not
prove that assessments agree. Differing semantic content enters the existing
neutral queue unless another reason already requires that review. Before
finalization, check the selected records together: retained settings ownership
must not contradict a selected consolidation, and references to proposed
operations must resolve to the selected operation set. Do not discard a specific
supported assessment in favor of generic prose merely to hide a conflict.
It performs neutral review for every disagreement or one-sided finding and for
all material-risk classes: consent ownership; client/server
routing; active deletion or consolidation; loader/destination/page-view,
ecommerce, paid-media, or identity change; code/template replacement; high-
fan-out or cross-market shared settings; unknown integrations; and projected High
or Critical operations.

The reconciliation input contains both sealed audits, exact raw coordinates,
independently reconstructed facts, and the contract. The agent must preserve
which conclusions came from each audit, expose every disagreement, and decide
without voting or silently preferring one audit. It may confirm, narrow, reject,
or keep a decision blocked; it cannot invent a third actionable target. Record
the reconciliation agent/context labels and exact locked input/output hashes.
Each neutral row exposes `allowed_evidence_citations`, the deterministic union of
its locked source coordinates and exact JSON paths inside locked neutral evidence.
Authored citations must be exact members of that list.

For an accepted actionable proposal or a non-neutral agreement, preserve one
verified review's complete canonical payload, including its assessment prose,
evidence boundary and decision citations. Matching the structured action alone
is insufficient. Put the reconciler's explanation in `reconciliation_rationale`,
and the neutral check's allowed citations in its own verification fields. A
required neutral review may instead reject or narrow a proposal to a supported
non-actionable decision. Never retain an inadequate claim just to pass the gate;
report the exact owning decision that requires repair.

In an authored neutral unit row, explicitly select the present `audit-a` or
`audit-b` decision with `selected_audit_id`; the finalizer copies that exact
comparison's complete sealed payload. Leave `non_actionable_decision` empty.
For supported non-actionable narrowing/rejection, leave the selector empty and
author `non_actionable_decision` with canonical semantic fields and allowed
`evidence_citations` only. Operations and extra fields are not accepted there.
Exactly one alternative is required. Verification rationale and citations remain
separate from the chosen decision. Unit rows do not accept manually authored
`canonical_decision`. Finalization and sealed-result reconstruction resolve the
same explicit choice and verify the expanded payload against it. This replaces
copying, not evidence review, disagreement resolution or cross-record checks.

When directly editing source reconciliation JSON, use bounded
patches anchored to exact row IDs. After each batch, check JSON parsing, complete
row membership, and unchanged locked fields against the immutable scaffold or
queue before continuing. A successful text patch is not a validation result.
If a draft is damaged, restore its locked content from that reference, preserve
validated authored rows, and repair only the affected draft; do not restart the
audits or infer replacement judgments.

Reconciliation scaffolds and the neutral-verification queue are reproducible
projections of both sealed audits. They are partitioned into deterministic units
of at most 30 comparisons so the same fresh reconciler can complete the whole
queue without one oversized edit. One locked manifest names every unit and row;
one small completion record carries the reconciler identity. Finalisation
reconstructs the manifest, membership, scaffolds, and queue and requires exact
equality, including closed nested rows, before authored dispositions can
influence a canonical decision. A self-rehashed scaffold or expected-answer hint
is not evidence.

## Stage 6 — Exact Operations And Deterministic Target Validation

Only reconciled and required-neutral-verified decisions enter target synthesis.
Operations support creates, additions, changes, named-field removals, remaps,
renames, pauses, and deletions with stable IDs, dependencies, exact source-bound
values, static
verification, and rollback. The synthesiser cannot make a new semantic choice.
Every write surface, including name and paused state, participates in the same
cross-operation conflict model. Blank or no-op rename/pause actions block.
The complete operation packet is a pure projection of sealed reconciliation;
every downstream gate rebuilds it and requires exact semantic equality rather
than trusting a locally consistent packet seal.

Use `scripts/gtm_target_validation.py` to reconstruct the operation packet from
sealed reconciliation and simulate the complete packet from the locked original
in dependency order. Check references, dependencies, conflicting writes,
protected objects, and the implemented consent/routing safeguards. Recompute
the simulated container's canonical scan and assurance to verify derived facts.
These deterministic checks do not reopen semantic obligations, call target
reviewers, or create new recommendations.

Graph checks compare source and target issues, including repeated broken-reference
occurrences within one consumer, and reject new failures. Unchanged
source reference/dependency issues retain their reconciled dispositions and are
recorded in the validation proof; a pass does not relabel them as repaired.

The five saved artifacts under `target-validation/` are
`projected-container.json`, `canonical-scan.json`, `scan-assurance.json`,
`validation-proof.json`, and `validation-seal.json`. The module exposes
`validate_target` and `target_validation_seal_errors`. The seal check reconstructs
the result from the locked original and sealed predecessors; self-rehashed
substitutes cannot become authority. Canonical sealing binds that result in
`target_validation` and reconstructs the exact canonical record and manifest.

A pass proves only the implemented static checks. It does not prove runtime
behaviour or that no further optimisation could be found. There are no semantic
target-review cycles or convergence gate. Trace a concrete validation failure to
its affected operation and owning decision. Object-matched candidates are not
proven owners; unresolved diagnostics require focused dependency/action inspection,
not reopening the whole packet. Never erase a finding
or invent an external owner question simply to obtain a pass.

## Stage 7 — Human Delivery

After deterministic target validation, seal one canonical record and transform
it through the rules in `references/03-rules/workbook-delivery.md`. The delivery layer may change
declared prose only. It cannot create a finding, target, operation, evidence
boundary, priority, or confidence value.

Reconstruct the delivery map exactly from the independently rebuilt canonical
record and require its seal and closed inventory to match. Workbook fidelity
compares visible delivery with that canonical projection, never with a mutable
map treated as its own authority.

A missing or incorrect canonical delivery field stops Stage 7. For a user-
authorized focused repair, pass the exact decision IDs and a concrete reason to
`scripts/gtm_audit_repair.py`. It validates the prior package and creates a new
working successor retaining source locks, scan, assurance, ledger, checkpoints,
both complete audits, seals, and histories. Only generated downstream outputs are
excluded from the copy; the predecessor stays unchanged. The repair receipt
identifies each exact owning source record and its prior seal.

Repair the stage that owns the defect. If a source judgment is defective, use a
fresh amendment context for its audit owner and the existing source-audit
amendment protocol. A reconciliation-only error keeps both source audits and
seals unchanged. Preserve unaffected judgments and the original peer-blind
evidence boundaries. Then reconstruct reconciliation in one
fresh context and rerun target synthesis, target validation, canonical sealing,
and the dependent workbook gates. This does not restart the complete source
audits or release repair evidence through new checkpoints.

The helper neither authors amendments nor carries semantic conclusions into new
scan evidence. A fresh reconciler may reuse a prior neutral conclusion only when
the newly reconstructed comparison, both source decisions, and neutral evidence
match the prior scaffolds exactly. An unchanged ID or hash alone is insufficient.
The reconciler owns changed rows and fresh completion provenance; the helper
does not automatically transfer verdicts. Stage 7 never patches a sealed record.

## Speed Without Weakening Trust

Speed comes from parallel Audit A/B work, family-local shards, one reusable fact
layer, focused assurance, targeted neutral checks instead of a third full audit,
deterministically prefilled agreement rows, one authored neutral decision projected
to its owning comparison, per-shard validation, hash-bound resume, and deterministic
workbook generation.
None may reduce obligation coverage, expose one audit to the other, turn judgment
into a fact, or skip combined target validation.
