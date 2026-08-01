# Cleanup Operation Schema

Compile operations only from three validated reviews. Audit findings describe a
problem; operations describe an exact proposed mutation.

The compiled packet uses schema version 4. It carries the source, context, and shared-fact hashes. It also carries
a decision ledger covering every source obligation, execution phases,
projected object counts by layer, and a target-state preservation entry for
every source-confirmed measurement family.

Compilation is fail-closed on source identity. The source must be a complete
ContainerVersion shape with modeled entity layers, valid object records, and
unique IDs. Missing or duplicate IDs, malformed entity lists, or an unmodeled
top-level list block operations instead of being silently ignored.

## Contents

- Dispositions and human fields
- Source identity, layer coverage, and behavior-impact alignment
- Structured creations, additions, field changes, remaps, deletions, and renames
- Consolidation and challenge review
- Merge/conflict rules and action completeness
- Row-level approval contract

## Dispositions

Use one:

- `cleanup_operation`
- `keep`
- `documented_exception`
- `owner_decision_needed`
- `container_evidence_limit`
- `not_applicable`

Operational findings use `documented_exception` rather than `keep` so every
mechanical anomaly remains visible. For a deterministic operational defect,
only `cleanup_operation` or a source-locked `documented_exception` is valid in
the final plan. A locked `review_candidate` may also use `keep` or a precise
`owner_decision_needed`; a locked true business choice may use the owner
decision. Configuration and architecture
may use `container_evidence_limit` or `not_applicable` only where their own
validators and evidence boundary allow it.

An unresolved owner or evidence-limit decision is not an empty fallback. It
contains one precise question and one concrete recommended action. A final plan
cannot leave a deterministic operational defect or source-known configuration
repair in `owner_decision_needed`. If a confirmed configuration Issue genuinely
requires an owner-selected replacement, its recommendation names the object,
defect ID or exact evidence anchor, and concrete repair/remap/removal direction.

## Required Human Fields

Each operation contains:

- unique `operation_key` and generated `operation_id`;
- title, area, and supported problem type;
- concrete problem and why it matters;
- expected clean state;
- exact proposed action;
- preconditions, QA steps, and rollback;
- priority, confidence, and execution readiness;
- `priority_basis` with active reachability, impact classes, evidence
  confidence, reversibility, owner dependency, an evidence-calibrated floor,
  and any below-floor review signal; this explains ordering but creates no new
  approval gate;
- source run(s), source review IDs, and evidence object keys;
- affected mutation objects;
- affected measurement-family IDs and the business behavior retained through
  the target state.

Use the shared taxonomy in `scripts/gtm_taxonomy.py`. Do not combine unrelated
issues under `Generic hygiene batch` merely to reduce rows.

Each compiled operation also carries `execution_safety`:

- `server_coupled` and exact behavior-bearing route hosts;
- `configured_activation_risk`, which means the mutation can change static
  configured reachability and never claims that a tag fired live;
- `approval.scope`: High/Critical, active, consent/security, server-coupled,
  and activation-relevant operations are individually approved; only exact
  low-risk non-active bundles are bulk-eligible;
- risk-based decommission strategy. Active, paused, uncertain, sensitive,
  server-coupled, or activation-relevant deletions quarantine first and need
  separate post-observation deletion approval. Proven inactive low-risk
  objects can be deleted directly after exact readback.

No fixed soak duration is universal. Choose an observation window that covers
the relevant traffic/business cycle. Do not rename an object merely to simulate
quarantine.

## Row-Level Approval Contract

The compiled packet contains `approval_contract` schema 1. Its packet hash binds
the full ordered operation surface, and each operation hash binds that row's ID,
mutation, safety, preconditions, rollback, and human decision fields.

Generate a response from the packet rather than composing a free-form list. The
response must contain every operation exactly once with one of:

- `Approve`: the exact row may proceed after all preflight conditions pass;
- `Reject`: it remains in the decision record and is not executed; or
- `Amend`: the proposed row is not executable until the operation packet,
  simulation, workbook, and approval response are regenerated.

The validator rejects a missing, duplicated, foreign, stale, or hash-mismatched
row. Row order may change because the operation ID and content hash remain the
identity. Approval does not imply the separate
`server_coupled`, `configured_activation_risk`, or post-observation deletion
confirmation. The execution guard reads either the validated response or direct
CLI flags, never both.

The compiled packet does not carry runtime-test contracts. An external outcome
that the export cannot prove remains a container-evidence boundary and cannot
relabel a source-visible defect as a runtime question. Do not prescribe GTM
Preview, browser, CMP, network, vendor, or server-side verification here; use
the separately scoped `gtm-preview-recette` skill only if the analyst later
requests runtime acceptance work.

`target_organization` is a projection of exact rename, folder, and paused-
lifecycle operations plus unresolved policy decisions. It cannot invent a
folder placement, target count, or cosmetic move that no source decision and
structured mutation support.

## Structured Mutations

### Field Change

```json
{
  "object_key": "tag:123",
  "json_path": "$.containerVersion.tag[4].parameter[2].value",
  "before": "{{Old Variable}}",
  "after": "{{Canonical Variable}}"
}
```

### Object Creation

```json
{
  "layer": "variable",
  "object": {
    "variableId": "99",
    "name": "Constant - Currency",
    "type": "c",
    "parameter": [{"type": "TEMPLATE", "key": "value", "value": "EUR"}]
  },
  "reason": "Create the missing source required by the approved target state."
}
```

The object must be complete and use an identity that does not already exist.

### Missing Field Or List Addition

```json
{
  "object_key": "tag:123",
  "json_path": "$.containerVersion.tag[4].parameter",
  "mode": "append",
  "value": {"type": "TEMPLATE", "key": "currency", "value": "{{Currency}}"},
  "reason": "Add the approved currency parameter to the existing event tag."
}
```

Use `set` for one missing object field, `append` for a list tail, and `insert`
with an exact index for a list position. Do not represent a missing field as a
change with a fabricated `before` value.

### Consumer Remap

```json
{
  "from_object_key": "trigger:10",
  "to_object_key": "trigger:20",
  "consumer_object_keys": ["tag:5", "tag:8"]
}
```

List the exact complete source-graph consumer set. A partial consumer move is a
field change, not a source-object remap. Variable remaps update `{{Name}}`; trigger
remaps update firing/blocking/group IDs; tag remaps update setup/teardown names;
folder remaps update parent IDs.

Zone boundary remaps update boundary trigger IDs. Name-based references in tags,
variables, Google tag configurations, templates, clients, transformations, and
Zones must resolve to exactly one source object; an ambiguous name is not a
valid remap target.

### Deletion

```json
{
  "object_key": "variable:21",
  "reason": "Duplicates variable 20 after all consumers are remapped."
}
```

### Rename

```json
{
  "object_key": "variable:20",
  "before": "Items",
  "after": "DLV - ecommerce.items"
}
```

Renames must remain unique within the GTM layer and update name-based references.
Field changes and renames must have different before/after values. A no-op is
not an operation and cannot satisfy an architecture cleanup obligation. Every
field addition/change path must sit under the source object named by its
`object_key`; pairing a valid key with another object's path is invalid.

## Decision Ledger And Execution Order

The decision ledger contains one row for every operational finding,
configuration object, architecture family, and relationship comparison. Each
row states its originating review ID, disposition, and linked operation ID when
cleanup is selected. No source obligation may disappear during reconciliation.
If exact operations delete every object behind a decision, resolve it to those
operations; if they leave a canonical survivor, narrow or resolve it to that
target state. Deleting a recommended canonical object is a hard conflict.
When Run 1 and a Run-3 comparison raise the same complete nonempty object-set
choice, preserve both source judgments but present the Run-3 decision or
operation once. This reconciliation is explicit in the ledger and is not an
accepted-risk exception. When an exact Unicode/whitespace-only field change
repairs every missing terminal used by downstream objects, link those dependent
configuration decisions to the upstream operation rather than duplicating an
owner question or field change.

Human presentation may batch homogeneous duplicate, unused, naming, folder, or
generic hygiene operations. The JSON operations remain atomic, and every
operation ID, structured mutation, affected object, approval choice, and QA
must remain recoverable exactly once from the visible plan.
Visible wording explains the concrete GTM behavior and exact change in analyst
language. Machine paths, hashes, validator phrases, and generic business-impact
boilerplate remain proof, not the primary explanation.

Apply approved operations in dependency-safe phases: create objects; add missing
fields/list members; apply logic correction; remap consumers; flatten trigger
groups and sequencing; rename; delete; then readback validation. The simulated
packet records before/after/delta counts for tags, triggers, variables,
templates, folders, clients, transformations, Zones, Google tag configurations,
and built-ins where applicable.

## Consolidation

Every consolidation identifies:

- `canonical_object_key`;
- why variants are equivalent at configuration and architecture level;
- every consumer remap;
- every non-canonical deletion;
- expected post-remap unused objects;
- QA and rollback.

An unused duplicate may require no remap, but still requires canonical selection
and deletion. Sanitation consolidation must align with an architecture operation.

## Challenge Review

High/Critical operations require source recheck, active/paused and scope check,
plausible alternative explanation, and confirmed/downgraded/rejected/blocked
verdict. This protects consent, revenue, paid-media, server-routing, and
multi-market changes from over-inference.
When identical mutations merge, retain a valid challenge from the highest-risk
lenses and never discard a blocked, rejected, or downgraded verdict because a
lower-risk row appeared first.

## Merge And Conflict Rules

- Reconcile operations when their complete structured mutations are identical,
  even if independent lenses use different wording or operation keys.
- Fold a deletion-only operation into one unambiguous broader operation when
  all of its exact object deletions are a subset of that operation; retain both
  source lenses and execute each deletion once. Do not choose between competing
  broader payloads.
- Compose generated text changes only when object key, normalized JSON path,
  and before value match; unrelated fields never coalesce merely because both
  operations contain changes.
- Preserve every lens rationale and source reference in the reconciled packet.
- Reject one operation key reused for different structured mutations.
- Require every source change/addition path to belong to the exact array entry
  identified by its `object_key`; a matching layer with another object index is
  still invalid.
- Reject different targets for one field, rename, or remap source.
- Reject deleting an object that is changed elsewhere.
- Reject remapping to an object selected for deletion.
- Reject cross-layer or unsupported-layer remaps and any remap that creates a
  dependency cycle through its consumer.
- Reject newly duplicated final names after applying the complete accepted
  creation, rename, and deletion set.
- Re-run consumer coverage, remap cycle, final-name, and mutation-conflict
  validation on each completed run's full operation set and again on the merged
  cross-run set.
- Reject mutation of an unresolved or intentional-variant architecture comparison.
- Reconcile every behavior-impacting change with architecture, even when it is
  not a consolidation. Logic, destination, trigger, routing, consent, schedule,
  sequencing, and deletion changes must be supported by architecture or blocked
  when architecture keeps the behavior or remains unresolved.
- Require architecture support for creations that introduce a new behavioral
  object or route. Export-only metadata, notes, folders, and reference-safe
  naming changes do not become behavior changes merely because their JSON differs.

## Action Completeness And Approval

Compile every justified operation into one proposed action set. Action
completeness passes only when:

- each cleanup disposition links to a compiled operation;
- each deterministic operational defect is an operation or intake-locked
  documented exception, while each retained review candidate includes
  source-specific proof of its intentional distinction;
- each source-known configuration correction is an operation; an owner-bound
  Issue instead carries the exact source-specific remediation contract above;
- each genuine owner or evidence-limit decision includes the analyst's concrete
  recommended action.

Do not classify operations into cleanup levels or defer them through an
aggressiveness setting. Before mutation, the analyst approves all operations or
an explicit list of operation IDs. Any changed selection requires a regenerated
future-state simulation before execution.
