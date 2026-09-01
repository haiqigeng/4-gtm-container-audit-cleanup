---
name: gtm-container-audit-cleanup
description: Audit and optimize one complete Google Tag Manager web container from locked JSON or equivalent read-only evidence, using an independently assured canonical scan, two host-scoped complete semantic audits, neutral reconciliation, deterministic fixed-point target validation, and one human analyst workbook. Use for web-container defects, duplicates, configuration, consent/routing, client-side server transport, Google settings inheritance, trigger/blocker architecture, firing priority, custom code, naming, consolidation, and greenfield-quality target design. Do not use for a server-container audit, GTM Preview or browser/runtime QA, tracking-plan design, legal decisions, GTM mutation/import/version/publication, execution approval, change logs, or audit deltas.
---

# GTM Container Audit And Cleanup

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

## Required Workflow

Follow one workflow only. There is no three-run, one-audit, reduced-depth,
same-context, legacy-workbook, or alternate-XLSX fallback.

### 1. Lock Evidence

Resolve one complete unambiguous ContainerVersion export or equivalent read-only
evidence. Confirm only when source or outcome is ambiguous. Lock source, context,
runtime skill identity, audit contract, vendor registry, and optional approved
requirements. Respect exact `do_not_touch` object keys.

Accept one web-container source only. Do not accept or request a server-container
export. Audit client-side transporter configuration and consent forwarding, then
state downstream server-container processing as outside this skill's evidence.

Build a new package with `scripts/gtm_audit_package_build.py`. Package creation
must pass runtime identity and independent raw-source scan assurance before any
semantic review. Never overwrite an existing package.

When a version-sensitive product, template, CMP, or vendor rule is absent or
stale, do not mutate the skill while auditing. Mark the affected obligation as
`container_evidence_limit`, identify one research owner and the exact official
evidence needed, and keep dependent recommendations blocked. Registry maintenance
is a separate, explicitly requested skill-evolution action; after that action is
validated, start a new audit package rather than changing an in-flight package.

### 2. Preserve Fact/Judgment Separation

Treat `canonical-scan.json` and `scan-assurance.json` as neutral evidence. The
scanner may generate candidates; it may not decide correctness, necessity,
priority, consolidation, or target architecture. The independent assurance path
must reread raw source and pass every applicable critical identity.

Use the typed `obligation-ledger.json`. Every object, chain, family,
relationship, singleton, source-owned branch/leaf/recursive trace, executable
code segment, and container-level method receives work or a source-counted zero.
Area 1 closes through evidence and assurance status, areas 2–26 through the two
semantic audits, and area 27 through synthesis and fixed-point proof.

### 3. Run Two Host-Scoped Complete Audits

Run Audit A and Audit B concurrently in separate fresh contexts over separate
allowlisted bundles created by `scripts/gtm_cleanroom_audit.py`. The execution
host must make the peer bundle and prohibited downstream artifacts inaccessible
and issue the receipt bound to the exact bundle manifest. The validator proves
receipt consistency, bundle integrity, and context separation; it cannot replace
host access control. The orchestrator coordinates but authors neither audit.

Audit A traverses object/chain first; Audit B traverses family/target first. Both
complete every applicable semantic obligation in areas 2–26 and close object,
chain, family, relationship, singleton, shared-infrastructure, and container
coverage. Different traversal does not mean different scope.

Each audit seals its source-only checkpoint before approved requirement evidence
is released. Audit B is also generated-candidate-blind before its checkpoint.
Later inputs may add work but may not rewrite checkpointed discovery.

Treat every reasoning-context ID and host-isolation receipt ID as a workflow-wide
single-use identity. The checkpoint and initial seal of one source audit may
retain their shared identity because they are one continuous review owner; no
different source audit, neutral verifier, projection review, editorial pass,
fidelity review, or workbook-only reader may reuse either ID. Enforce this with
the shared registry in `scripts/gtm_reasoning_identity.py`, including immutable
history and prior workbook builds.

Use deterministic family work units and one shared-infrastructure unit when the
bundle requires sharding. Never reduce evidence or reviewer count for context
size. Validate and immutably seal both audits. If host-enforced isolation is
unavailable, block.

### 4. Reconcile And Verify Neutrally

Use `scripts/gtm_reconciliation.py`. Compare atomic decisions by exact obligation,
subjects, family/relationship, and target. Expose agreements, complementary
conclusions, one-sided findings, conflicts, and differing evidence boundaries.
Never vote, average, or silently select an audit.

Send every disagreement, one-sided finding, and material-risk class listed in
the workflow reference to a fresh neutral verifier. The neutral input excludes
audit identity, rationale, vote count, and expected answer. It may confirm,
narrow, reject, or keep blocked; it cannot invent a third actionable target.
Each neutral verifier receives one hash-bound allowlisted bundle in a host-scoped
context with an enforced receipt. Its context and receipt identities must be new
relative to source checkpoints, source audits, peer neutrals, projection reviews,
and every prior cycle. If the host cannot enforce that boundary, block.

### 5. Synthesize And Prove The Target

Use `scripts/gtm_target_synthesis.py` to compile only reconciled, required-
verified decisions into exact creates, additions, changes, named-field removals,
remaps, renames, pauses, deletions, dependencies, static verification, and
rollback. Synthesis may
not introduce a new semantic choice.

Use `scripts/gtm_fixed_point.py` and `scripts/gtm_projection_review.py`. Every
cycle starts from the locked original, applies the complete packet, reruns global
scan and independent assurance, and sends new/changed semantic obligations to two
fresh host-scoped reviews plus required neutral checks. Permit at most three cycles.
Block as `non_convergent_target_state` on cycle-three actionability, recurring
actionable hashes, oscillation, conflicts, or no exact safe operation.
Construct each next cycle in staging and commit its decision record, operation
packet, and cycle directory together. Any candidate-cycle safety or assurance
failure preserves the last committed packet and decisions and returns the blocked
outcome; it may not leave a partial cycle.

Replay a stable packet from the locked original and require the complete hash
tuple to match. Then create the authoritative record with
`scripts/gtm_canonical_record.py`.

### 6. Build One Human Workbook

Use `scripts/gtm_delivery_mapper.py` only after canonical sealing. If a mandatory
delivery field is absent or semantically wrong, stop delivery. Build a new
semantic-successor package from the same locked source, bind it to the prior
canonical record and one approved repair brief, and rerun the complete workflow.
The repair becomes an obligation in both fresh audits and neutral reconciliation.
Delivery may never patch a canonical field or overwrite the sealed predecessor.

Run the editorial transformation in a fresh context. It may improve declared
prose fields only and must preserve every technical identifier and locked meaning.
Its context must also be fresh against every earlier workflow owner.

Use the workspace spreadsheet artifact runtime and the bundled
`scripts/gtm_workbook_build.mjs`; verify with
`scripts/gtm_workbook_verify.mjs`. If that runtime is unavailable, block instead
of authoring through another library. The workbook has `01 Overview`,
`02 Recommendations`, `03 Decisions Needed`, `04 Full Audit`, and `05 Custom
Code` only when source-applicable.

Use `scripts/gtm_delivery_reviews.py` to create separately scoped fidelity and
workbook-only reader checks. Render and visually inspect every visible sheet.
Both checks require workflow-globally fresh contexts and host receipts, not only
identities distinct from each other and the editorial pass.
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

Sealed semantic artifacts are immutable. An amendment uses a fresh context bound
to the prior seal and append-only history before canonical sealing. After
canonical sealing, a semantic or fidelity defect starts one immutable successor
package bound to the predecessor record and same locked source, then reruns the
whole workflow. Presentation-only defects create a new editorial artifact and
rebuild.

Use `references/02-commands/validation-commands.md` for exact commands and
`references/02-commands/forward-test-prompts.md` for release proof. Deliver only
when every criterion in `references/01-skill/acceptance-criteria.md` passes.
