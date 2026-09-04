---
name: gtm-container-audit-optimize
description: Audit and optimize one user-selected Google Tag Manager web-container export in one comprehensive pass, with two independent audits, reconciliation, static validation of proposed changes, and one analyst workbook. Use for defects, duplicates, configuration, consent and triggers, Google settings inheritance, web-side client-to-server transport, custom code, naming, and consolidation. Excludes server-container audits, runtime QA, tracking-plan design, legal decisions, and GTM mutation or publication.
---

# GTM Container Audit And Optimize

## Outcome

Make the supplied container as clean, correct, simple, and maintainable as if a
senior web analyst configured it today from an empty container for the same proven
needs. From container-visible evidence, decide what is wrong, what is materially
non-optimal, what should stay and why, and what remains an owner decision or
evidence limit. Produce one exact static target and one trustworthy analyst
workbook backed by a sealed canonical JSON record.

Read before work:

- `references/01-skill/purpose.md`
- `references/01-skill/inputs-outputs.md`
- `references/01-skill/non-goals.md`
- `references/01-skill/acceptance-criteria.md`
- `references/03-rules/audit-coverage.md`
- `references/03-rules/workflow-and-assurance.md`
- `references/03-rules/domain-contracts.md`
- `references/03-rules/workbook-delivery.md`

Use `references/03-rules/source-map.md` to route any deeper question. Use
`references/03-rules/container-json-guide.md` for export shape and
`references/03-rules/naming-standardization.md` for names.

## Hard Boundary

Stop at the validated workbook. Never mutate GTM, generate/apply an import,
create a GTM version, publish, certify post-change state, create an approval
packet or change log, or describe an operation as executed. A future
implementation task needs separate explicit authorization and a mutation-capable
skill.

Do not claim runtime firing, network/vendor receipt, live data-layer values,
cookie/CMP UI behaviour, GA4 property settings, legal compliance, runtime
performance, or unseen server enforcement. Use the exact static evidence boundary
in every affected conclusion.

## User Interaction

The user must explicitly supply or identify exactly one authoritative source file.
Never search the workspace for a likely export, infer a source file, or choose
among multiple supplied sources. If the user has not explicitly identified
exactly one file, send exactly:

`Please provide or identify the exact GTM web-container export file you want me to audit. I will not search for or infer a source file.`

Then stop and wait for the user. After the user identifies the file, validate it
without asking for facts already present in that source. Ask for other information
only when it cannot be inferred and its absence prevents a safe conclusion;
otherwise retain the gap as an owner decision or container evidence limit.
Wording for every non-source question and every blocked outcome is left to the
agent.

After, and only after, the workbook passes every completion gate, begin the final
response with exactly:

`Audit complete: [x] recommended operations, [y] owner decisions and [z] evidence limits. No GTM changes were made.`

Replace `[x]`, `[y]`, and `[z]` with the workbook’s canonical counts. Wording
after that sentence is left to the agent.

## Required Workflow

Follow one workflow only. There is no three-run, one-audit, reduced-depth,
same-context, legacy-workbook, or alternate-XLSX fallback.

A delegated stage is complete only when its required output passes the applicable
validation and sealing gates. If an assigned agent returns with unfinished work
and no concrete blocker, the coordinator resumes that agent's retained context
from the last valid step, preserving completed work and the stage's input and
independence boundaries. Report a genuine capability, evidence, or authorization
blocker when it prevents the next required step.

One normal execution has one comprehensive source-audit pass. The two independent
audits are complementary safeguards within that pass, not successive optimisation
cycles. Do not re-audit simulated targets for further opportunities. Repeated runs
to improve the skill belong only to separately authorized development evaluation.

### 1. Lock Evidence

Validate the one complete unambiguous ContainerVersion export or equivalent
read-only evidence explicitly selected by the user. Lock source, context, runtime
skill identity, audit contract, vendor registry, and optional approved
requirements. Respect exact `do_not_touch` object keys.

Before package creation, load the existing workspace spreadsheet dependency
paths and run `scripts/gtm_workbook_build.mjs --preflight` with that bundled Node
runtime. If the check fails, block before semantic work. Do not substitute another
Node.js runtime or XLSX library.

Accept one web-container source only. Do not accept or request a server-container
export and do not model server-container Clients, Transformations, or templates.
Audit the web-container side of client-to-server transport and consent forwarding,
then state downstream server-container processing as outside this skill's evidence.

Produce scan assurance in its required fresh agent context, then build a new
package with `scripts/gtm_audit_package_build.py` using that artifact. Package
creation reconstructs and validates the complete assurance result before any
semantic review. Never overwrite an existing package.

When a version-sensitive product, template, CMP, or vendor rule is absent or
stale, do not mutate the skill while auditing. Mark the affected obligation as
`container_evidence_limit`, identify one research owner and the exact official
evidence needed, and keep dependent recommendations blocked. Registry maintenance
is a separate, explicitly requested skill-evolution action; after that action is
validated, start a new audit package rather than changing an in-flight package.

### 2. Preserve Fact/Judgment Separation

Treat `canonical-scan.json` and `scan-assurance.json` as neutral evidence. The
canonical scan is deterministic. The scanner may generate candidates; it may not
decide correctness, necessity, priority, consolidation, or target architecture.
Run scan assurance in a separate fresh agent context that receives the locked raw
source, assurance rules, and canonical scan identity but no semantic findings. It
must reread raw source and pass every applicable critical identity. Record its
agent/context labels plus locked input and output hashes. When the orchestrator
supplies exact source, scan, registry, and output paths, run the maintained scan-
assurance command directly. Do not add shell path checks, searches, directory
enumeration, or inferred filenames.

Use the typed `obligation-ledger.json`. The assured scan and compact checkpoint
account for every literal object, branch, leaf, trace, and executable-code line.
The two audits receive transversal semantic work for every generated sanitation
or optimisation candidate, source family, relationship candidate, tag-control
topology, custom-code object, applicable configured branch group, container
closure, and source-counted zero. Area 1 closes through evidence and assurance
status, areas 2–26 through those two semantic audits, and area 27 through
synthesis and static target validation.

### 3. Run Two Complete Independent Audits

Run Audit A and Audit B concurrently in separate fresh agent contexts over
separate locked input bundles created by `scripts/gtm_cleanroom_audit.py`. Both
may receive the same locked source facts, audit contract, and version-locked
skill rules. Neither may receive the peer's findings, discoveries, rationale,
scratch work, or target proposals until both audits are complete and sealed. The
orchestrator coordinates but authors neither audit.

Audit A traverses object/chain first; Audit B traverses family/target first. Both
complete every applicable transversal semantic obligation in areas 2–26 and
close candidate, family, relationship, tag-control topology, custom-code object,
shared-infrastructure, and container coverage. Literal object and branch
completeness comes from the assured scan plus compact source checkpoint; it is
not repeated as thousands of generic semantic decisions. Different traversal
does not mean different scope.

Find the complete improvement in this pass. For each proposed consolidation or
removal, inspect all consumers and remaining dependencies; include evidenced
consequential cleanup in the same proposal. Close shared settings, trigger/blocker
ownership, loader/destination families, naming, and custom-code behaviour across
the whole container before sealing. Do not defer source-visible opportunities to
a later target audit. Preserve justified variants and genuine owner decisions.

An unwritten operation is unfinished audit work, not a reason to ask the owner.
When one object has a source-proven safe repair and a separate unresolved policy
or ownership issue, keep the repair actionable and the question separate using
the existing atomic decision/discovery contract. Do not hide both in one broad
owner-decision profile. Conversely, never invent null defaults, equivalence, or
retirement authority just to increase the recommendation count.

Each audit seals its source-only checkpoint before approved requirement evidence
is released. Audit B is also generated-candidate-blind before its checkpoint.
Later inputs may add work but may not rewrite checkpointed discovery.

A pending checkpoint is the assigned audit agent's work queue, not a blocker.
The agent reviews its complete locked inventory, then directly completes the
compact checkpoint by binding `reviewed_inventory_sha256` to the supplied
`inventory_sha256`, recording provenance, any source-only discoveries, and one
source-only conclusion. The checkpoint does not duplicate per-object prose,
families, relationships, or candidates already owned by the assured scan and
later transversal obligations. Record each optional source-only discovery as one
concise non-blank string; these notes are not semantic decisions. Complete the
checkpoint directly in its scaffold.

Before checkpoint sealing, an audit bundle has no `work-units` directory. The
checkpoint command creates `work-units/work-unit-manifest.json`; only then may
the agent review and complete the declared work units. Use each manifest
record's exact `filename` under
`audit-bundles/<audit-id>/work-units/<filename>` and never inspect the peer audit.
`audit-scratch/<audit-id>` contains only `audit-plan.json`; it never contains
locked evidence or work units.

Keep semantic-audit execution within the assigned evidence. Read only the exact
assigned bundle files, the locked shared rules, and the declared work-unit filenames. The audit
contract and JSON scaffolds are the complete schema. Read large evidence files
in bounded portions using line ranges or selected JSON properties/array slices
from those exact files. Review each distinct source fact and its relationships;
repeated serialization need not be reread. If output truncates, reduce the portion
and resume at the unread content before claiming coverage. Direct exact-path
reads and in-memory selection, such as PowerShell `Get-Content -LiteralPath`
with `Select-Object` or `ConvertFrom-Json`, are allowed when no filesystem tool
is available. Do not search implementation source with `rg`, `grep`, or
another discovery command, enumerate unknown paths, or run exploratory shell
commands. Use the documented checkpoint, plan scaffold/apply, validate and seal
commands for package transitions, with structured edits confined to the isolated
declarative audit plan. Source audits and neutral reconciliation may also perform
the bounded static-predicate checks in `references/03-rules/workflow-and-assurance.md`.
Reconciliation's
scaffold command performs the subsequent sealed-audit and history check.

After checkpoint release, read `release-manifest.json` and its declared evidence.
Resolve a work-unit row's `obligation_id` in the released `obligation-ledger.json`
for its complete evidence, and its `candidate_id` in the released canonical scan
for candidate details. Audit B's candidate-blind phase has ended at this point;
the work-unit rows are authoring records, not substitutes for that evidence.
Use `scripts/gtm_audit_plan.py` to scaffold exactly
`audit-scratch/<audit-id>/audit-plan.json`. The assigned fresh agent authors
compact decision profiles there. The scaffold locks neutral candidate groups
from locked area, mechanism, fact, applicability, and verification-trigger fields
so the agent does not rebuild obligation-ID plumbing. These are not verdicts:
review every obligation and split any candidate whose judgment, target, evidence
meaning, or action differs. Assign complete candidates through compact
`decision_profiles`; use exact `obligation_overrides` for all obligations that
must split from a candidate. The applicator expands profiles and proves every
obligation is assigned exactly once. Every candidate names its exact obligation
IDs and may share one decision only when the criteria assessment, target,
preserved distinctions, next step, and evidence meaning are genuinely identical.
An exact shared operation may use one OP-* ID across multiple obligations under
the workflow's shared-operation rule; each obligation keeps its own evidence and
coverage validation. Author a shared profile or override once when its assessment
fits all members. Candidate membership is locked; profiles and overrides contain
the nested decision. Use the
case-sensitive priority and confidence values in `authoring_contract`. An
actionable decision includes the declared authored `operation_proposal`. This
includes an uppercase `operation_id` matching the exact pattern and example in
`authoring_contract`. Its target state, preconditions, static verification, and
rollback are specific human-readable non-blank strings, without a word-count quota;
`preconditions` is never a list. Author verification and rollback once inside
the operation; the applicator projects them into the canonical decision. It also
derives the source decision identity and fills omitted unused action lists and
dependencies with empty lists. Supply every necessary action and dependency;
follow the declared operation-family and structured-action contract.
Action-row `json_path` values are object-relative paths such as
`$.priority`, never full `$.containerVersion...` source coordinates.
Changes and named-field removals use `before_source_sha256`, copied from the
locked source identity, instead of literal `before`. The object key and path
identify the old value. Never copy credentials into a proposal or its prose;
recovery requires the canonical operation and matching locked source. See the
command contract for the exact representation.
The applicator validates the combined operation set against the locked source
before writing; Stage 5 performs dependency-ordered target simulation. This
exact-ID grouping removes repeated prose without using
broad selectors or replacing evidence-specific judgment. Missing runtime evidence
limits runtime claims; it does not justify deferring a container-visible static verdict.
The maintained applicator
requires exactly one decision per obligation, validates every decision,
operation, discovery, manifest, and work unit before writing, and performs the
deterministic work-unit merge when sharding applies. Never create a substitute
helper, write into the peer scratch directory, or expose one plan to the peer.
Keep plan `open_discoveries` empty unless the audit found a genuinely new
semantic record that can satisfy the complete structured discovery contract.
Checkpoint string notes are not plan discoveries and must not be copied there.

Before checkpoint sealing, the only audit-bundle filenames are explicit. Both
audits use `audit-contract.json`, `bundle-manifest.json`, `context.json`,
`locked-source.json`, `source-checkpoint.json`, and `vendor-registry.toml`.
Audit A additionally has `canonical-scan.json`, `scan-assurance.json`, and
`source-obligations.json`; Audit B additionally has `blind-inventory.json` and
must not seek candidate artifacts. Its inventory lists every object's source-leaf
coordinates and dependencies; read the corresponding full values in
`locked-source.json`, rather than expecting duplicated value previews in the
index. Set checkpoint `input_manifest_sha256` from
the exact `bundle_manifest_sha256` field in `bundle-manifest.json`. There is no
`input-manifest.json`. After the checkpoint command, use only its declared
outputs plus `work-units/work-unit-manifest.json` and each exact `filename`.

Record lightweight provenance for each audit: an agent label, a context label,
the locked input-bundle hash, and the sealed output hash. Audit A and Audit B
must use distinct agent and context labels.

Use the existing checkpoint, manifest and isolated plan to continue across audit
work units and context boundaries.

Use deterministic whole-family work units when the bundle requires sharding.
Partition transversal shared-infrastructure obligations by audit area into
bounded deterministic units; never split a single obligation or implementation
family. Never reduce evidence or reviewer count for context size. Validate and
immutably seal both audits. If the AI environment cannot run the required
separate fresh agent contexts, block with a concise capability message.

Author decision fields by class. Every decision needs its class, concise
criteria assessment, priority, confidence, and locked evidence citations.
Recommendations additionally need current behavior, material consequence or
benefit, preserved distinctions, target direction, next step, static
verification, rollback, and one exact operation. Owner decisions and evidence
limits need only their class-specific question or boundary plus the context
required to act. Do not pad appropriate-as-configured or not-applicable records
with repetitive delivery prose.

Do not hide an exact source-proven obligation inside a broad retained, owner, or
evidence-limit profile. A locked source-known configuration repair must remain an
exact actionable decision. A blocker proven unable to intersect any firing event
is a defect with that blocker removed. A visible default consent writer firing
later than Consent Initialization is a defect moved to Consent Initialization.
Unused Custom HTML `document.write` support with no call is a material
optimisation using its locked one-field repair. These rules classify only facts
already proven by the locked container; they do not convert ambiguous candidates
or runtime gaps into recommendations.

A source-known field repair must appear exactly in the proposal when its object
is retained; other justified actions may accompany it. If that same proposal
explicitly retires the object, do not require a redundant intermediate field edit.
Retirement still needs independent justification, consumer safety, and neutral
verification; pausing or retiring another object does not satisfy the repair.

### 4. Reconcile And Verify Neutrally

Use `scripts/gtm_reconciliation.py`. Compare atomic decisions by exact obligation,
subjects, family/relationship, and target. Expose agreements, complementary
conclusions, one-sided findings, conflicts, and differing evidence boundaries.
Never vote, average, or silently select an audit.

Treat reconciliation scaffolds and neutral queues as deterministic views, never
as authority. Finalisation reconstructs them from the two sealed audits and
requires exact equality before it accepts authored dispositions.

Run reconciliation in a separate fresh agent context after both audits are
complete. Its locked input contains both sealed audits and the evidence required
to resolve them. It compares every disagreement, one-sided finding, and material-
risk class listed in the workflow reference. This fresh reconciliation agent may
perform the neutral review itself: it may confirm, narrow, reject, or keep a
decision blocked, but cannot invent a third actionable target. Record its agent
and context labels plus locked input and sealed output hashes.
Each neutral row publishes `allowed_evidence_citations`, deterministically built
from its locked source coordinates and exact JSON paths inside its locked neutral
evidence. Cite only values from that list; do not infer or normalize a path.

The reconciliation scaffold creates
`reconciliation-units/manifest.json`, bounded unit files named exactly by that
manifest, and `reconciliation-completion.json`. The one fresh reconciler reviews
and completes every declared neutral-verification row sequentially in the same
context, then records its identity and `complete` status in the completion file.
It does not edit comparison rows: non-neutral agreements are deterministically
prefilled from sealed audit decisions, and each neutral comparison is projected
from its completed verification. In each neutral row, select `audit-a` or `audit-b`
in `selected_audit_id` to retain that row's complete sealed source decision, leaving
`non_actionable_decision` empty. For a supported non-actionable narrowing or
rejection, leave the selection empty and author `non_actionable_decision` using
canonical semantic fields and exact allowed `evidence_citations`, with no operation
or extra fields. Populate exactly one alternative. Write the verification's own
citations and rationale separately. The finalizer expands the selected payload;
do not copy or edit `canonical_decision` in authored unit rows.
Finalisation reconstructs the manifest and unit
membership, merges every row exactly once, validates the complete semantic
result, and only then writes and seals the canonical reconciliation files.

### 5. Synthesize And Validate The Target

Use `scripts/gtm_target_synthesis.py` to compile only reconciled, required-
verified decisions into exact creates, additions, changes, named-field removals,
remaps, renames, pauses, deletions, dependencies, static verification, and
rollback. Synthesis may
not introduce a new semantic choice.

Use `scripts/gtm_target_validation.py` to validate the combined packet against the
locked original. Reconstruct the packet from sealed reconciliation, simulate it,
and verify references, dependencies, conflicting writes, protected objects, and
the implemented consent/routing safeguards. Recompute projected facts and scan
assurance to verify the simulation; this does not open semantic review queues or
create new recommendations. Reconstruct the saved result to reject self-rehashed
substitutes. A pass proves only the implemented static checks, not runtime
behaviour or that no further optimisation could ever be found.

A concrete failure must be traced to the affected operation and owning decision.
An object match is a repair candidate, not proof of causality. If the diagnostic
cannot resolve ownership, inspect only the failed reference and relevant actions
before selecting records; never treat the whole packet as the owner. Repair
that work and its dependants, then rerun the affected validation; do not restart
the complete audits or launch a target-discovery round. Preserve valid evidence
and completed judgments. Never drop a finding merely to obtain a pass. Seal the
canonical record with `scripts/gtm_canonical_record.py` only after validation.

### 6. Build One Human Workbook

Use `scripts/gtm_delivery_mapper.py` only after canonical sealing. If a mandatory
delivery field is absent or semantically wrong, stop delivery and reopen its
owning records with `scripts/gtm_audit_repair.py`. The working successor preserves
source evidence, checkpoints, both source audits and their seals; the predecessor
remains unchanged. Repair the owning stage: amend a source audit only when its
own decision is defective; for a reconciliation-only error, retain both source
audits and seals unchanged. Reconcile the affected work and rebuild dependent
validation and delivery. Do not rerun ingestion or the complete audits. Delivery may never patch
a canonical field or overwrite a sealed predecessor.
The delivery map must be an exact deterministic projection of the independently
reconstructed canonical record; workbook fidelity is checked against that same
authority, not against a mutable delivery artifact.

Run the editorial transformation after canonical sealing. It may improve declared
prose fields only and must preserve every technical identifier and locked meaning.

Use the workspace spreadsheet artifact runtime and the bundled
`scripts/gtm_workbook_build.mjs`; verify with
`scripts/gtm_workbook_verify.mjs`. If that runtime is unavailable, block instead
of authoring through another library. The workbook has `01 Overview`,
`02 Recommendations`, `03 Decisions Needed`, `04 Full Audit`, and `05 Custom
Code` only when source-applicable.

Use `scripts/gtm_delivery_reviews.py` to create separately scoped fidelity and
workbook-only reader checks. Run them in separate fresh agent contexts with
distinct labels and locked inputs; neither receives the other's findings. Record
each input and output hash. Render and visually inspect every visible sheet.
Pass exact row/field recovery, comments/navigation/dimensions, absence of
unexpected formulas or renderer artifacts, privacy, formula injection, fidelity,
readability, and layout checks before sealing delivery.

## Decision Rules

Use exactly one class per primary obligation: `defect`,
`correct_but_materially_non_optimal`, `justified_as_is`, `owner_decision`,
`container_evidence_limit`, or source-proven `not_applicable`.

For consent, classify the route first. Except confirmed Advanced Consent Mode,
all direct browser/vendor tags use a consent-free positive trigger and one
reusable denial blocker. A page-load tag may use a documented CMP timing event;
a later action keeps its business event. Do not configure consent in both the
positive route and blocker, and do not use Additional Consent Checks as the gate.
Built-In Consent Checks remain intrinsic metadata.

For each direct page-load route, assess whether the configured CMP
lifecycle/update opportunity can re-evaluate eligibility after a later grant, or
whether locked context explicitly approves a reload dependency. If neither is
established, keep the target as an owner decision or evidence limit. Never solve
that uncertainty by moving granted-state consent into the positive trigger.

Confirm Advanced Consent Mode only from a locked
`advanced_consent_mode_approvals` row with exact destination ID, direct-browser
or client-to-server scope, exact route host where applicable, approved status,
and concrete approval evidence. The matching source must also expose coherent
default and update writers, consent types, and Consent Initialization timing;
native Google capability or an unscoped approval is insufficient.

A pure client-to-server transporter has firing triggers only, no client consent
gate, and one complete canonical consent value configured once and inherited by
every transported event. Classify and remediate a route as pure only when locked
approved context names every route host as having a downstream server consent-
gating owner. Without that ownership confirmation, keep client-gate removal
blocked as an owner decision or container evidence limit. Mixed direct/server
routes are judged per branch.

Treat explicit firing priority as suspect, including `0`. Keep nonzero priority
only for an evidenced start-order need among same-event competitors; sequencing,
not priority, owns completion dependencies.

Share Google configuration-wide values through one Configuration Settings owner
and genuinely shared event values through one Event Settings owner. Keep event-
specific values local and preserve justified overrides. Repetition creates a
candidate only; type, shape, source, timing, consent, route, destination, consumer,
and ownership compatibility determine the verdict.

## Repair And Completion

For a source amendment, pass `--amendment-of`, `--agent-id` and `--context-id`
to the existing plan `apply` command. It checks the current parent and fresh
identity before writes and projects provenance into the generated audit. Author
the isolated plan, not the large generated audit JSON; validate and seal with
that same parent hash using the documented commands.

Preserve sealed predecessors and repair the exact owning records. Source
amendments use a fresh agent context, explicit prior-seal binding, the unchanged
source checkpoint, and the maintained immutable snapshot/history protocol.
After canonical sealing, make semantic or fidelity repairs in a working successor
using the repair command above. Reuse prior reconciliation conclusions only when
their full comparison inputs and neutral evidence still match and validate; a
fresh reconciler owns changed rows. Presentation-only repairs use a new editorial
artifact and rebuild.

Follow `references/03-rules/workflow-and-assurance.md` for the complete amendment,
artifact-integrity, path-safety, recovery, and focused-repair requirements. Use the
maintained commands to enforce those requirements and preserve unaffected work;
repair does not repeat broad discovery or bypass a validation gate.

Use `references/02-commands/validation-commands.md` for exact commands and
`references/02-commands/forward-test-prompts.md` for release proof. Deliver only
when every criterion in `references/01-skill/acceptance-criteria.md` passes.
