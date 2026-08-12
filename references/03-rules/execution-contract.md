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
Before intake, require `.skill-build-manifest.json` to match the actual runtime
tree exactly for an installed/bundled copy. A clean Git checkout may establish
the same exact identity from its tracked commit and runtime file set; a dirty
checkout or an unverifiable tree blocks package creation.

Generate and present the context preflight before semantic review. Distinguish
analyst-provided context, high-confidence deterministic inference, and
unresolved fields. Record unresolved business, naming, ownership, lifecycle,
folder, or preferred-target context as nonblocking owner decisions and continue
all three reviews. They block only an affected mutation whose exact target
depends on the answer. Only partial/ambiguous source identity, an unmodelled
entity layer, or missing proof that prevents an exact configuration judgment
blocks semantic review.

Validate ContainerVersion identity before semantic work. The wrapped/direct
root, known entity-layer registry, layer arrays, required IDs, and unique IDs
must be unambiguous. Unknown entity-like layers and invalid identity block all
three reviews; there is no partial or reduced-depth fallback.

The package gate recomputes context content and reconstructs shared facts from
the locked export. Matching hash strings with changed or fabricated content do
not satisfy source integrity.

An explicitly analyst-approved tracking plan may be normalized as a separate
requirement artifact. Preserve exact source file/sheet/row/raw-field hashes and
provide it only to Runs 2 and 3. It is never part of container-derived shared
facts or Run 1, and exact identifier links do not authorize inferred semantic
replacement.

## Required Pipeline

```text
raw container evidence
  + provided/inferred audit context
  + optional, separately labelled approved requirements for Runs 2 and 3
  -> source model and canonical deterministic facts
  -> independent Run 1: operational sanitation
  -> independent Run 2: configuration correctness
  -> independent Run 3: business architecture
  -> three-run completion gate
  -> contradiction-aware operation reconciliation
  -> fixed-point cleanup closure and dependency-safe operation order
  -> measurement-preservation and target-state projection
  -> future-state graph simulation
  -> canonical human cleanup plan and existing gates
  -> post-gate analyst readability transformation
  -> hash-locked row-level operation approval and route selection
  -> optional execution or import JSON
  -> complete readback certification
  -> separate post-execution change log
```

The shared fact layer normalizes identity, leaves, references, consumers,
terminal sources, trigger logic, code/formula signals, consent routes, and
behavior signatures. It may not contain correctness, necessity, duplication,
consolidation, or cleanup judgments.

The three runs may execute in parallel after source lock. Package creation
builds one physical allowlisted `review-bundles/<run>/` directory per run. Give
each complete directory, and no other audit output, to a distinct fresh
reasoning context. The root orchestrator coordinates, validates, and seals; it
does not author a run. Each run may read its raw export copy, locked context,
shared deterministic facts, run rules, and own scaffold, but must not read or
copy another run's verdicts. Sharing facts removes extraction drift; physical
input separation and independent judgments preserve genuine challenge.

The package manifest locks one input contract per run: required, optional, and
prohibited artifact roles plus source, context, and shared-fact hashes. Each
completed review attests its actual roles. A missing role, undeclared role,
foreign verdict artifact, reconciled output, or repository test helper fails
that run before reconciliation.
Deterministic tools may scaffold, shard, merge, validate, and seal source obligations;
they may not bulk-author semantic verdicts, rationales, dispositions, or
operations. Every completed run records a distinct reasoning-context identity.
The root seals a validator-passing bundle-local review with that real context
identity and promotes it to the canonical package. The completion gate requires
three distinct seals, matching input-bundle hashes, and review hashes that have
not changed after sealing. Reusing one identity, bypassing the bundle, changing
a sealed review, or declaring a semantic bulk-completion artifact fails before
reconciliation. When three fresh contexts are unavailable, report the full
audit as blocked; there is no same-context certification fallback.

If a validator exposes an error after a run was sealed, the root does not edit
that verdict artifact. Reopen only that run in a new reviewer context and reseal
with `--amendment-of <current-seal-sha256>`. Sealing rejects same-context,
missing-parent, and stale-parent amendments and archives the prior seal plus
exact review artifact before promotion. This append-only chain preserves
reviewer ownership without restarting valid foreign runs.

Use `review-scratch/<run>/` for all notes, temporary extracts, and draft prompts.
Only manifest-declared files may remain in a sealed bundle. If accidental scratch
appears there, sealing moves it to the run scratch directory, records the move, and
resumes without deletion; changed declared inputs still fail. Never delete or overwrite
an unidentified artifact to make a bundle pass.

Package creation automatically uses source-locked shards when a run contains
more than 40 primary review items or Run 2 exceeds 120 authored behavior work
units. The package manifest records each run's strategy, evidence-obligation
count, authored-work count, and shard directory under `review_work_units`;
reviews below the applicable limits remain single files.
Manual splitting remains available for legacy packages or a deliberately lower
bound on an unusually dense object.

Every shard remains part of one run and the merge must recover the exact
source-generated obligation set. Chunking is an execution strategy, not a
reduced-depth mode. Architecture uses a dedicated discovery shard for
analyst-added `DISC-*` comparisons and its all-object attestation; the merged
run cannot become complete while either is pending. Current Run-2 shards expose
only source-hashed reviewer-editable completion overlays while the adjacent
bundle-local base retains every generated branch, reference trace, contract,
technical finding, D3 check, and custom-code line. Merge reconstructs full rows
and rejects extra, missing, or changed-source fields. New packages do not create
per-obligation micro-shards; their validator remains available only for legacy
package resumability. Check each completed shard against its source locks,
manifest identities, and exact completion set before continuing. The check
catches local corruption early; the merged run must still pass its authoritative
run validator. The merge persists the checked shard filename, kind, completed-item
count, and content hash, then reads back the merged review. If one shard fails, repair
and recheck only that named shard; do not restart completed shards or continue from an
unverified write.

A local shard or validator failure is not an intake question and does not pause
the whole audit. Repair only its reviewer-owned completion fields in the same run
(or use the fresh amendment context above after sealing), recheck, and continue.
Escalate to the user only for the true source/tooling blockers defined by this
contract; never ask permission merely to resume deterministic validation work.

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

The artifact retains deterministic, source-cited semantic summaries and an
exact ledger of every branch, trace, contract, technical fact, code segment, and
D3 check. These generated renderings are not correctness certification. Every
object receives one authored correctness basis, and every escalated behavior
group receives a source-specific conclusion across purpose/output,
execution/scope, inputs/consumers, consent/sequence, destination/routing, code,
and vendor contract as applicable. A failed group links to a concrete defect.

The reviewer artifact contains evidence and allowed source paths, not the
validator's field-by-field grading terms. The validator reconstructs those
terms independently from the locked source. Evidence acquisition and exact-once
coverage remain exhaustive even though routine source narration is not authored
repeatedly. Only a deterministically eligible simple folder, built-in, constant,
or Data Layer Variable may retain a routine completion basis. Any code, formula,
lookup, regex, consent/vendor/server role, finding, ambiguity, owner decision,
unresolved dependency, high fan-out, or unknown risk requires `deep` authored
review. Discovery of any issue in a simple row forces escalation.

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

After the three sealed judgments reconcile, compute cleanup closure to a fixed
point from the complete locked consumer graph. If approved source operations
remove or detach the last consumer of a trigger, variable, built-in, folder, or
template, add one visible, separately approvable reconciliation operation with
the exact prerequisite operations. Do not feed this consequence back into any
review, treat it as a fourth scan, add runtime roots, or infer that a business
tag is obsolete. Topologically order the resulting operations so consumers are
retired or remapped before their dependencies.

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
2. add `A1 Overview`, `A2 Actions`, `A3 Decisions`, `A4 Audit Register`, and
   `A5 Custom HTML` before content-identical canonical tabs hidden by default;
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
Unresolved business, naming, folder, paused-lifecycle, ownership, or preferred-target
context is handled the same way: continue all three scans and expose the decision in A3.
Only partial or ambiguous source identity, an unmodelled entity layer, missing proof
that prevents a complete configuration judgment, or unavailable required tooling blocks
the audit itself. A genuine owner decision may block execution of its affected mutation
but never unrelated audit work or workbook delivery.

## Plan And Operation Approval

Audit and recommendation depth are always full. Before approval, the route may
remain `Pending user selection`.
When action completeness fails, the human output is a blocked draft: one visible
blocked row and accurate Summary counts, with no partial operation list
presented for approval.

After plan delivery, ask for:

1. one `Approve`, `Reject`, or `Amend` response for every exact operation;
2. route: direct GTM/API/MCP or import JSON.

Do not ask for an aggressiveness mode. Recommend the best safe future state once.
Low-risk, non-active exact operations may be presented as one bulk-eligible
approval bundle. A sensitive word in the name of a structurally unreferenced
deletion-only trigger/variable does not create a fictitious active consent or
security control. High/Critical, active, genuinely consent/security,
server-coupled, and configured-activation-risk operations remain individually
approved. Run the execution preflight against exact `do_not_touch` keys, every
dependency prerequisite, the passing simulated future state, and a fresh
complete workspace readback that still equals the audited object graph before
either mutation route.
Approval controls which exact operations may be executed; rejected or amended
operations stay visible in the analyst's decision record and require the future
state to be regenerated before mutation. A subset is a staged, incomplete
cleanup and cannot inherit the full plan's completion claim.

Generate the response template from the schema-4 operation packet. Its packet
hash locks the complete approval surface and each operation hash locks the row.
Validation rejects missing, duplicate, foreign, or changed rows. Server-coupled,
configured-activation-risk, and post-observation confirmations remain separate
from `Approve` and must also pass the execution preflight.

An optional audit delta may compare two independently completed and sealed full
packages after their own scans and reconciliation. It reports objective source,
finding, operation, decision, family, and count changes only. It never makes a
changed-only audit or carries an earlier verdict, confidence, or score forward.

## Completion States

`Complete` requires:

- source-model coverage `pass` or `pass_with_integrity_findings`, with every
  integrity finding retained in the operational review;
- matching source, context, and shared-fact hashes across all three runs;
- three distinct validator-passing isolation seals whose bundle and canonical-review hashes match;
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
no unlinked field change. Regenerate the final field-level result and change log
from that readback; it is the sole authoritative execution result. A successful
API response, intermediate mutation record, partial object check, or executed
workbook built from a failing certification is not execution certification.

Otherwise report `Incomplete / blocked` with the exact missing artifact or
source-bound reason. Do not claim completion because the container is large or
the review is token-intensive. Chunk work while preserving all obligations.
