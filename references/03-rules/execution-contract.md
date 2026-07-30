# Authoritative Execution Contract

This is the canonical full audit-and-cleanup contract. A different reference may add a
domain rule but may not weaken this workflow.

## Contents

- Evidence boundary and source-integrity gate
- Required pipeline and the three independent runs
- Reconciliation and future-state validation
- Plan, operation approval, and completion states

## Evidence Boundary

Use a complete GTM JSON export or equivalent complete read-only configuration.
The container proves configured logic, not live website behavior, network
delivery, CMP state, vendor acceptance, or an unseen server container.

Lock one source filename and SHA-256. Build a persistent context artifact and a
canonical deterministic fact artifact. Every generated review must carry the
source, context, and shared-fact hashes. A changed export or material context
change starts a new review package.

Record the runnable skill's project version and deterministic runtime-tree hash
in the package manifest. When an installed copy and a development checkout are
both present, compare their runtime identities before choosing one. A git branch
name or matching version string alone does not prove equal skill content.

Generate and present the context preflight before semantic review. Distinguish
analyst-provided context, high-confidence deterministic inference, and
unresolved fields. A material question pauses semantic review; a non-material
question remains visible without creating a new package or completion gate.

Validate ContainerVersion identity before semantic work. The wrapped/direct
root, known entity-layer registry, layer arrays, required IDs, and unique IDs
must be unambiguous. Unknown entity-like layers and invalid identity block all
three reviews; there is no partial or reduced-depth fallback.

The package gate recomputes context content and reconstructs shared facts from
the locked export. Matching hash strings with changed or fabricated content do
not satisfy source integrity.

## Required Pipeline

```text
raw container evidence
  + provided/inferred audit context
  -> source model and canonical deterministic facts
  -> independent Run 1: operational sanitation
  -> independent Run 2: configuration correctness
  -> independent Run 3: business architecture
  -> three-run completion gate
  -> contradiction-aware operation reconciliation
  -> measurement-preservation and target-state projection
  -> future-state graph simulation
  -> canonical human cleanup plan and existing gates
  -> post-gate analyst readability transformation
  -> explicit operation approval and route selection
  -> optional execution or import JSON
  -> complete readback certification
  -> separate post-execution change log
```

The shared fact layer normalizes identity, leaves, references, consumers,
terminal sources, trigger logic, code/formula signals, consent routes, and
behavior signatures. It may not contain correctness, necessity, duplication,
consolidation, or cleanup judgments.

The three runs may execute in parallel after source lock. Each may read the raw
export and shared deterministic facts, but must not read or copy another run's
verdicts. Each completes its own artifact and passes its own validator. Sharing
facts removes extraction drift; keeping judgments separate preserves genuine
independent challenge.

The package manifest locks one input contract per run: required, optional, and
prohibited artifact roles plus source, context, and shared-fact hashes. Each
completed review attests its actual roles. A missing role, undeclared role,
foreign verdict artifact, reconciled output, or repository test helper fails
that run before reconciliation.
Deterministic tools may scaffold, shard, merge, and validate source obligations;
they may not bulk-author semantic verdicts, rationales, dispositions, or
operations. Every completed run records a distinct reasoning-context identity.
Reusing one identity across two runs, or declaring a semantic bulk-completion
artifact, fails before reconciliation.

Prefer a fresh reasoning context for each run. If only one context is
available, exclude completed verdict artifacts from the next run's inputs and
reload only the export, context, shared facts, and current scaffold. This is an
input-discipline rule; it does not add another verdict or completion engine.

Package creation automatically uses source-locked shards when a run contains
more than 40 primary review items or one configuration obligation group exceeds
30 items. The package manifest records each run's strategy and shard directory
under `review_work_units`; reviews below both limits remain single files.
Manual splitting remains available for legacy packages or a deliberately lower
bound on an unusually dense object.

Every shard remains part of one run and the merge must recover the exact
source-generated obligation set. Chunking is an execution strategy, not a
reduced-depth mode. Architecture uses a dedicated discovery shard for
analyst-added `DISC-*` comparisons and its all-object attestation; the merged
run cannot become complete while either is pending. Configuration obligation
shards contain at most 30 obligations and must recover every generated branch,
reference trace, contract, technical finding, D3 cross-check, and custom-code
line exactly once and in source order. Check each completed shard against its
source locks, manifest identities, and exact completion set before continuing.
The check catches local corruption early; the merged run must still pass its
authoritative run validator.

## Run 1: Operational Sanitation

Source: `operational_scan.json`, `shared_facts.json`, and raw export.

Decision artifact: `operational_review.json`.

Purpose: guarantee basic cleanup coverage even when business analysis is hard.
Every nonzero finding receives `cleanup_operation`, `documented_exception`,
or `owner_decision_needed`. Action completeness rejects an owner state for a
deterministic structural defect whose safe source-visible target is known. A
source-proven lifecycle or organisation condition whose safe outcome depends on
rollback retention, vendor ownership, or final folder taxonomy is instead a
`business_decision`; it remains visible with one precise question and one
recommended target. A `documented_exception` is valid only when the locked
context identifies that finding, signature, or object and gives a specific
owner reason that the review preserves. `container_evidence_limit` and
`not_applicable` cannot erase a deterministic nonzero finding.
Every zero module retains its source-counted proof row.
The mandatory registry is fixed independently of the scan output. Reachability
starts at active direct tags and configured Zone/client/Google-tag/
transformation roots, traverses recursive dependencies including enabled
built-ins, and does not treat isolated cycles as usage.

Run rules: `operational-sanitation.md`.

## Run 2: Configuration Correctness

Source: raw object branches, `shared_facts.json`, consumer/dependency graph,
technical code facts, vendor registry, and current official documentation.

Decision artifact: `configuration_review.json`.

Purpose: prove literal behavior and correctness for every tag, trigger,
variable, Zone, custom template, client, Google tag configuration, and
transformation. Review every logic leaf, every recursive reference node and
hop, every consumer, every applicable official contract topic, and all custom-
code lines. Duplicate name resolution retains all custom/built-in candidates as
ambiguous. A generic summary or copied parameter list fails.

Review rows and all nested identity sets (branches, D3 checks, contracts,
technical findings, traces, and parser segments) are unique and exact-once.
Malformed or duplicate rows fail before dictionary indexing. Deterministic
source obligations propagate through branch, D3, defect, overall verdict, and
the corresponding official contract; same-destination peer server/type/consent
facts create an explicit inheritance review rather than an inferred route.

An unavailable or failed optional JavaScript parser creates a mandatory parser-
coverage limit. It may be explicitly bounded by complete line-by-line review,
with source-specific behavior for every individual segment, but empty AST facts
cannot be interpreted as a successful AST scan. Mixed
Custom HTML retains every detected vendor plus separate unknown-host research
obligations. Unknown official sources are registry-bound, validated, and
rescaffolded before they can certify a topic.

Every semantic field cites one or more generated source paths selected for that
claim and names source-derived behavior facts. Citations alone do not validate a
generic statement. Every object also completes the exact generated D3
cross-check set for purpose/output, execution/scope, input/output/consumer, and
consent/sequence, plus code and vendor-contract alignment when applicable. A
failed cross-check links to a concrete defect.

Run rules: `configuration-correctness.md` and `domain-contracts.md`.

## Run 3: Business Architecture

Source: raw export, `shared_facts.json`, source-derived family chains, and
relationship candidates.

Decision artifact: `architecture_review.json`.

Purpose: decide whether individually plausible objects form a necessary,
non-overlapping, maintainable measurement architecture. Review every tag family
or Zone/Google-tag/server intake/transformation family, every object in each
execution chain, and every generated cross-object candidate. Same-child Zones
and same-destination tags/Google tag configurations are mandatory comparisons.
Then run open discovery across all source objects and add source-bound
comparisons the deterministic queue missed.
The generated method coverage, candidate IDs, all-object review scope, and
source-scope hashes are immutable. Each method review must account for that
exact scope and cite source-derived objects or comparisons in its conclusion.
Each `DISC-*` row is attributed to its declared methods and inherits unsafe
policies for deterministic relationships among its members. Actionable verdicts
must affect candidate behavior, and unsafe runtime/owner questions preserve
negative evidence polarity and relationship-specific terms.

Run rules: `business-architecture.md`.

## Reconciliation

Do not average or vote across runs.

Behavior-changing edits, additions, remaps, deletions, and creations cannot
proceed through a family or comparison that Run 3 preserves or leaves
unresolved. Metadata-only names, notes, export fields, and folder placement do
not trigger that behavior rule, but still require exact approved mutations.
Run-1-proven deletion of unused objects, objects reachable only through paused
tags deleted in the same operation, and paused tags is inactive-lifecycle
cleanup rather than a change to the active measurement graph. It does not need
a fabricated Run 3 relationship, but complete reference validation and the
future-state gate remain mandatory.

An exact source-bound, non-destructive Run-1 or Run-2 repair may proceed with
completed Run-3 family coverage rather than a duplicated architecture mutation.
It cannot create, delete, or remap an object and remains subject to simulation,
except that an exact impossible-blocker repair may delete the trigger it makes
orphan when the complete consumer graph proves no other use.
An explicit Run-3 cleanup decision resolves weaker candidate rows only for that
same complete structured mutation; overlapping object IDs alone are never
enough.

- A configuration issue may produce a fix even when the object is structurally valid.
- An exact operational duplicate may be deleted only when architecture confirms
  configuration/business equivalence. Once confirmed, architecture emits the
  consolidation operation; approval is handled by the operation gate rather
  than a redundant owner choice between identical copies.
- A correctly configured object may still be unnecessary at family level.
- An architecture operation may redesign several individually correct objects.
- An unresolved owner or container-evidence decision blocks conflicting mutation.

Operations with identical structured mutations may reconcile even when the
three lenses use different human wording or operation keys. Preserve every lens
rationale and source reference. Reusing one operation key for different
structured mutations is an error. Broad issue categories never merge
operations.
When one run proposes only deletions that are an exact subset of one
unambiguous broader operation, fold those deletion facts into that operation so
each object is deleted once and every evidence lens remains visible. Competing
broader action payloads remain a hard conflict.
The completion gate recompiles the three source reviews and requires the
supplied operation packet to match exactly; hand edits require
updating and revalidating the originating review.
Two generated text edits may compose only when they share object key,
normalized field path, and before value. Repairs to unrelated fields remain
separately approvable operations.
One exact mutation compiles to one operation packet even when several lenses
find it. The packet retains each lens's classification, rationale, and source
reference. A runtime-neutral label from one finding cannot suppress an
architecture decision required by another finding merged into that mutation.

Compilation creates a complete decision ledger. Every operational finding,
configuration object, architecture family, and comparison must have one final
disposition; every cleanup disposition must link to one compiled operation.
Reconciliation narrows or resolves decisions whose source objects disappear,
links the exact deletion operations, and rejects deletion of a recommended
canonical object. Action completeness rejects a source-known configuration fix
without an operation; an Issue requiring a genuine replacement choice must
name its object, defect ID/evidence anchor, and remediation direction.
Reconciliation represents one complete object-set owner choice once under the
architecture comparison while retaining each independent source judgment.
It also links downstream missing-reference decisions to an exact upstream
Unicode/whitespace repair when that operation fixes every missing terminal.

Compilation also creates a measurement-preservation projection for every
source-confirmed architecture family. It states whether the family is retained,
changed, owner-blocked, or limited by container evidence; links its operations;
and records required behavior, consent/routing context, and target state.
It also projects only source-backed target organisation. External behavior that
the export cannot prove remains a static, source-linked evidence boundary; this
skill does not create runtime test contracts or prescribe runtime acceptance
work.

## Future-State Gate

Apply structured operations to a copy of the export before delivery. Update
complete object creations, missing-field/list additions, variable references,
trigger IDs, trigger-group members, setup/teardown tag names, folders, field
values, names, and deletions. Re-run sanitation, regenerate deterministic
configuration obligations, and regenerate business-architecture relationship
candidates from the projected container.

Block when the simulated state:

- creates a missing reference or duplicate ID;
- creates a new sanitation finding;
- leaves an operational finding selected for cleanup unresolved;
- retains a deterministic configuration Issue that is neither fixed nor
  explicitly owner-blocked by a source-specific remediation decision;
- creates a relationship candidate outside an architecture-backed operation or,
  for a non-unsafe discovery-only candidate, explicit Run-3 retention decisions
  that cover every candidate pair;
- remaps to an object that is also deleted;
- applies conflicting values to one object field;
- deletes an object while another operation changes it.

The gate also reports projected before/after/delta counts by GTM layer. An
unexpected broad count change is a review blocker even when references remain
technically valid.

## Post-Gate Analyst Workbook

After the canonical eight-tab workbook passes its existing workbook gate and
all-sheet privacy scan, run the readability transformation defined in
`workbook-output-contract.md`. This is one final output step, not another audit
workflow:

1. copy the validated canonical workbook;
2. add the five lean analyst tabs;
3. project every decision-ledger record, operation, owner-decision source
   record, and Custom HTML tag;
4. run the independent readability gate.

The transformation cannot change a source fact, review verdict, disposition,
priority, operation, canonical-object direction, future-state result, or
completion state, and none of its output may feed back into the three runs.
Owner decisions are valid nonblocking output records. When the transformation
or its gate fails, reject only the derived workbook, keep and deliver the
canonical workbook, report the readability failure separately, and do not
rerun the audit.

## Plan And Operation Approval

Audit and recommendation depth are always full. Before approval, the route may
remain `Pending user selection`.
When action completeness fails, the human output is a blocked draft: one visible
blocked row and accurate Summary counts, with no partial operation list
presented for approval.

After plan approval, ask for:

1. exact operation IDs: approve all or an explicit subset;
2. route: direct GTM/API/MCP or import JSON.

Do not ask for an aggressiveness mode. Recommend the best safe future state once.
Low-risk, non-active exact operations may be presented as one bulk-eligible
approval bundle. High/Critical, active, consent/security, server-coupled, and
configured-activation-risk operations remain individually approved. Run the
execution preflight against exact `do_not_touch` keys and the passing simulated
future state before either mutation route.
Approval controls which exact operations may be executed; rejected or amended
operations stay visible in the analyst's decision record and require the future
state to be regenerated before mutation. A subset is a staged, incomplete
cleanup and cannot inherit the full plan's completion claim.

## Completion States

`Complete` requires:

- source-model coverage `pass` or `pass_with_integrity_findings`, with every
  integrity finding retained in the operational review;
- matching source, context, and shared-fact hashes across all three runs;
- all three run statuses `complete`;
- complete architecture open-discovery attestation and decision ledger;
- no review validator error;
- no reconciliation contradiction;
- action completeness `pass`;
- future-state gate `pass`;
- canonical cleanup workbook and privacy gate `pass`;
- no formula cell or unscanned hidden proof tab in a delivered workbook;
- a separate completed change log, when requested, links only exact
  field-level mutations to approved operation IDs.

A passing derived analyst workbook is the preferred deliverable but is not a
precondition for audit completion: its documented fallback is the already
passing canonical workbook.

For executed work, `Complete` additionally requires a complete workspace/export
readback that exactly equals the approved simulated future state and contains
no unlinked field change. A successful API response or partial object check is
not execution certification.

Otherwise report `Incomplete / blocked` with the exact missing artifact or
source-bound reason. Do not claim completion because the container is large or
the review is token-intensive. Chunk work while preserving all obligations.
