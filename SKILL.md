---
name: gtm-container-audit-optimize
description: Audit and optimize one complete Google Tag Manager web container from user-supplied locked JSON or equivalent read-only evidence, using a deterministic canonical scan, fresh-agent scan assurance, two complete independent semantic audits, fresh-agent reconciliation, deterministic fixed-point target validation, and one human analyst workbook. Use for web-container defects, duplicates, configuration, consent/routing, web-side client-to-server transport, Google settings inheritance, trigger/blocker architecture, firing priority, custom code, naming, consolidation, and greenfield-quality target design. Do not use for server-container exports or objects, GTM Preview or browser/runtime QA, tracking-plan design, legal decisions, GTM mutation/import/version/publication, execution approval, change logs, or audit deltas.
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
synthesis and fixed-point proof.

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
concise non-blank string; these notes are not semantic decisions. Do not create
or execute an audit-local helper.

Before checkpoint sealing, an audit bundle has no `work-units` directory. The
checkpoint command creates `work-units/work-unit-manifest.json`; only then may
the agent review and complete the declared work units. Use each manifest
record's exact `filename` under
`audit-bundles/<audit-id>/work-units/<filename>` and never inspect the peer audit.
`audit-scratch/<audit-id>` contains only `audit-plan.json`; it never contains
locked evidence or work units.

Semantic-audit execution is closed-command. Read only the exact assigned bundle
files, the locked shared rules, and the declared work-unit filenames. The audit
contract and JSON scaffolds are the complete schema. A direct exact-path file
read such as PowerShell `Get-Content -LiteralPath` is allowed when no filesystem
tool is available. Do not search implementation source with `rg`, `grep`, or
another discovery command, enumerate unknown paths, or run exploratory shell
commands. Other than exact-path reads and one structured edit of the isolated
declarative audit plan, the only executable commands are the documented
checkpoint, plan scaffold/apply, validate, seal, and post-seal validate gates.

After checkpoint release, use `scripts/gtm_audit_plan.py` to scaffold exactly
`audit-scratch/<audit-id>/audit-plan.json`. The assigned fresh agent authors
compact decision profiles there. The scaffold locks neutral candidate groups
from locked area, mechanism, fact, applicability, and verification-trigger fields
so the agent does not rebuild obligation-ID plumbing. These are not verdicts:
review every obligation and split any candidate whose judgment, target, evidence
meaning, or action differs. Assign complete candidates through compact
`decision_profiles`; use exact `obligation_overrides` for all obligations that
must split from a candidate. The applicator expands profiles and proves every
obligation is assigned exactly once. Every candidate names its exact obligation IDs and
may share one decision only when the criteria assessment, target, preserved
distinctions, next step, and evidence meaning are genuinely identical. Put each
actionable operation in its own one-obligation group because its operation and
target are unique. Each group has exactly `group_id`, `obligation_ids`, and a
nested `decision` object; never flatten decision fields into the group. Use the
case-sensitive priority and confidence values in `authoring_contract`. An
actionable decision includes the complete declared `operation_proposal`. This
includes an uppercase `operation_id` matching the exact pattern and example in
`authoring_contract`. Its target state, preconditions, static verification, and
rollback are human-readable strings meeting the contract's minimum word counts;
`preconditions` is never a list. Follow the same contract for exact source
decision identity, operation-family wording, structured-action presence, and
dependencies. Action-row `json_path` values are object-relative paths such as
`$.tagFiringPriority`, never full `$.containerVersion...` source coordinates.
The applicator runs the existing operation simulator against the locked source,
or locked projected source for a projection review, before writing. This exact-ID grouping removes repeated prose without using
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
must not seek candidate artifacts. Set checkpoint `input_manifest_sha256` from
the exact `bundle_manifest_sha256` field in `bundle-manifest.json`. There is no
`input-manifest.json`. After the checkpoint command, use only its declared
outputs plus `work-units/work-unit-manifest.json` and each exact `filename`.

Record lightweight provenance for each audit: an agent label, a context label,
the locked input-bundle hash, and the sealed output hash. Audit A and Audit B
must use distinct agent and context labels.

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

### 5. Synthesize And Prove The Target

Use `scripts/gtm_target_synthesis.py` to compile only reconciled, required-
verified decisions into exact creates, additions, changes, named-field removals,
remaps, renames, pauses, deletions, dependencies, static verification, and
rollback. Synthesis may
not introduce a new semantic choice.

Use `scripts/gtm_fixed_point.py` and `scripts/gtm_projection_review.py`. Every
cycle starts from the locked original, applies the complete packet, reruns global
scan and independent assurance, and sends every materially changed semantic
obligation to two fresh review agents. The two review agents receive the same
locked projected evidence but not each other's findings; reconcile their sealed
results in a fresh context. Each reviewer uses the same maintained declarative
plan command as the source audits, with one isolated
`projection-scratch/cycle-<nn>/<review-id>/review-plan.json`; never create a
projection-local resolver or infer a configured object from normalized display
text. Permit at most three cycles.
Block as `non_convergent_target_state` on cycle-three actionability, recurring
actionable hashes, oscillation, conflicts, or no exact safe operation.
Construct each next cycle in staging and commit its decision record, operation
packet, and cycle directory together. Any candidate-cycle safety or assurance
failure preserves the last committed packet and decisions and returns the blocked
outcome; it may not leave a partial cycle.

Replay a stable packet from the locked original and require the complete hash
tuple to match. Reconstruct the operation packet, projected evidence, fixed-point
proof, and canonical record from their sealed predecessors; reject any artifact
that only makes its own hashes internally consistent. Then create the
authoritative record with
`scripts/gtm_canonical_record.py`.

### 6. Build One Human Workbook

Use `scripts/gtm_delivery_mapper.py` only after canonical sealing. If a mandatory
delivery field is absent or semantically wrong, stop delivery. Build a new
semantic-successor package from the same locked source, bind it to the prior
canonical record and one approved repair brief, and rerun the complete workflow.
The repair becomes an obligation in both fresh audits and neutral reconciliation.
Delivery may never patch a canonical field or overwrite the sealed predecessor.
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

Sealed semantic artifacts are immutable. An amendment uses a fresh agent context
bound to the prior seal in the audit artifact, preserves
the immutable source checkpoint, seals an exact immutable snapshot of every
work-unit input used by that audit version, and writes append-only history before
canonical sealing. Every current or historical audit is revalidated against its
own self-contained regular-file snapshot, never against later live shard edits.
Recompute each unit's explicit immutable audit, source, ledger, family, and
membership identity, and deterministically reconstruct the audit decisions and
discoveries from those units; do not trust embedded digests or self-rehashed
merged-audit claims. Reconstruct the workload estimate from the locked scan,
assurance, and audit, and reject undeclared fields in workload, manifest, record,
unit, decision, discovery, operation proposal, or structured action rows. Do not
filter malformed or duplicate nested evidence: the completion proof must equal
one deterministically reconstructed closed object. Before any public workflow
command reads or writes package data, enumerate the complete package tree without
traversing redirects and reject every symlink, junction, or reparse point at the
root or any descendant. Apply the same fail-closed rule to generated workbook
outputs. After
canonical sealing, a semantic or fidelity defect starts one
immutable successor package bound to the predecessor record and same locked
source, then reruns the whole workflow. Presentation-only defects create a new
editorial artifact and rebuild.

Use `references/02-commands/validation-commands.md` for exact commands and
`references/02-commands/forward-test-prompts.md` for release proof. Deliver only
when every criterion in `references/01-skill/acceptance-criteria.md` passes.
