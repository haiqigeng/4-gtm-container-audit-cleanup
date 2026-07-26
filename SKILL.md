---
name: gtm-container-audit-cleanup
description: Perform heavy operational Google Tag Manager cleanup as a container-only expert web analyst. Start from a complete JSON export or equivalent read-only GTM evidence, exhaustively audit sanitation, recursive configuration and custom code, consent and routing, and business architecture; turn every substantiated finding into the simplest exact cleanup plan; and, when explicitly approved, execute through GTM/API/MCP or produce a validated import JSON and change log. Use for naming, consolidation, migration, repair, deletion, and target-state redesign. Do not use for GTM Preview, live browser/network/dataLayer/CMP/vendor QA, legal decisions, website implementation, unseen server containers, unapproved mutation, or publication.
---

# GTM Web Analyst Audit And Cleanup

Act as an experienced web analyst, not a mechanical duplicate finder. Use only complete container configuration and exported code as audit evidence.

## North Star

> Do the heavy operational work needed to leave an existing GTM container as clean, simple, well-organised and logically correct as its real measurement needs allow. Exhaustively identify every container-visible cleanup and optimisation opportunity, decide the exact safe disposition and target state for each, and, when authorised, execute and verify the approved changes without regressing necessary measurement, consent behaviour, routing or integrations.

The audit is the evidence foundation; the actionable cleanup plan and verified resulting container are the product. Keep machinery only when it improves discovery completeness, decision quality, execution safety, or regression prevention.

Read these before every full execution:

1. `references/01-skill/purpose.md`
2. `references/01-skill/inputs-outputs.md`
3. `references/01-skill/acceptance-criteria.md`
4. `references/03-rules/execution-contract.md`

Load other rules only when their topic applies.

## Intake

Collect or infer:

- complete GTM export/API evidence and container type;
- website/domain and business model;
- ecommerce, lead, publisher, media, market, CMP, and server-routing context;
- SPA status, canonical IDs, staging hosts, exact do-not-touch object keys, and naming policy when known;
- whether approved execution or import JSON is wanted after the mandatory audit and cleanup plan.

Ask concise questions before starting when material context is missing. Infer safe facts from the export and website context. Ask about unexplained prefixes, country/product variants, unclear event families, or legal/business ownership; do not ask for account/container names already present in the export. Read exported domain fields whether scalar or list-valued. Treat market codes, CMPs, publisher models, and server routes as confirmed only from specific behavior/scope evidence; arbitrary acronyms, generic consent words, advertising labels, or unrelated endpoint URLs remain candidates rather than facts.

Persist provided and inferred answers in `context.json`, including unresolved questions and the evidence basis for inference. Context may guide grouping and contract selection, but it may not replace container evidence or silently turn an assumption into a finding.

Before a fresh run, identify the runnable skill tree. Record its project version and deterministic runtime-tree hash in the audit package. If both an installed copy and a development checkout are available, compare them with `python -B scripts/gtm_skill_identity.py verify <expected-root> <actual-root>`; do not infer that equal folder names, branches, or version strings mean equal runtime content.

Before building review scaffolds, run the context model as an intake preflight:

```bash
python -B scripts/gtm_context_model.py container.json --pretty
```

Present supplied, high-confidence inferred, and unresolved fields separately. Ask only the generated material questions, then rebuild with the confirmed context. Non-material questions remain visible but do not create a new audit gate. Do not start semantic review while a material intake question is pending.

If the evidence is a compiled live script, partial UI screenshots, or another incomplete representation, mark the audit blocked and request a complete export or equivalent complete read-only API/UI evidence. Do not create a reduced audit mode or infer unseen container state.

## Non-Negotiable Architecture

A full audit consists of three independent runs against the same source and shared-fact hashes:

1. **Operational sanitation**
2. **Configuration correctness**
3. **Business architecture**

These are not headings inside one semantic pass. Build one canonical, deterministic fact layer for object identity, raw leaves, references, consumers, terminal sources, trigger logic, formula facts, consent routes, and behavior signatures. All runs may read these same source facts and the raw export. Facts must contain no cleanup, correctness, necessity, or duplication verdict.

Each run has its own obligations, decisions, validator, and failure status; it must not read another run's judgments. Technical custom code belongs to configuration correctness, not a fourth verdict engine. Reconcile only after all three pass.

Prefer a fresh reasoning context for each run. Otherwise load only the raw export, locked context, shared facts, and current scaffold. Each scaffold has an immutable input contract whose prohibited inputs include foreign verdicts, reconciled output, and test helpers; using them invalidates its attestation.
Semantic decisions must be authored in that run-specific context: tools may scaffold, shard, merge, or validate, but never bulk-fill judgments; each run records a distinct reasoning-context identity.

Audit depth is always complete. Approval changes execution, never what is checked or recommended.

## Workflow

### 1. Lock Evidence

- Preserve the raw export and SHA-256.
- Preserve the normalized audit context and its SHA-256.
- Inventory tags, triggers, variables, built-ins, folders, Zones, custom
  templates, clients, Google tag configurations, and transformations.
- Build dependency, consumer, setup/teardown, trigger-group, template, folder,
  destination, and active/paused maps.
- Infer business model and journey signals only from objects reachable from an
  active/configured root. Keep orphan logic in the audit without letting it
  redefine business context. A server-container transport URL is not evidence
  that Google tag gateway is enabled; only an explicit gateway signal may set
  that status.
- Build `shared_facts.json` once and require every run to bind to its hash.
- Lock each run's permitted input roles in the manifest; never edit its generated contract.
- Recompute both context and shared-fact content at the package gate; matching a
  copied hash without matching canonical content is a failure.
- Treat GTM system references such as `{{_event}}` and high-range system trigger
  IDs as system objects, not missing references.
- Keep unresolved exported references auditable as integrity findings. They do
  not justify skipping the remaining scannable container.

```bash
python -B scripts/gtm_audit_package_build.py container.json --out-dir audit-package --pretty
```

When analyst-supplied context exists, pass it as a JSON object:

```bash
python -B scripts/gtm_audit_package_build.py container.json --context audit-context.json --out-dir audit-package --pretty
```

For a large container, split each generated review independently into bounded shards with `scripts/gtm_review_shards.py`, complete every shard, and merge it back before validation. Sharding changes context size, never scope or evidence requirements. Architecture splitting creates a dedicated open-discovery shard; complete its `DISC-*` rows and attestation before merge. Do not combine shards from different runs, shared-fact hashes, context hashes, or source hashes.
Use `--max-obligations 30` or less for configuration reviews. The obligation manifest must recover every generated branch, trace, contract, technical finding, D3 cross-check, and custom-code line exactly once and in source order.
Keep exhaustive proof in the machine-readable artifacts. The human workbook summarizes each object, defect, decision, and action instead of repeating every passing leaf, trace node, or code line.
Write the visible plan for an experienced analyst: state the literal configured problem, why GTM behaves that way, the exact change, what is deliberately left unchanged, and the static readback. Do not expose validator prose, raw JSON paths, hashes, or generic “remove maintenance risk” boilerplate as the primary explanation.
Check each completed shard immediately against its base and manifest; this is early use of the existing locks, not a substitute for the final run validator:

```bash
python -B scripts/gtm_review_shards.py check audit-package/configuration_review.json configuration-shards completed-shard.json
```
### 2. Run Operational Sanitation Independently

Complete every finding in `audit-package/operational_review.json` through five
explicit inner passes: integrity; lifecycle/usage; exact/structural duplication;
trigger structure/lint; and folders/naming/legacy inventory. Check broken
references, unused and paused-only objects, exact duplicates, duplicate paths
and code, trigger groups, trigger contradictions/regex/blockers, tags invoked
only through sequencing, folders, built-ins, templates, legacy setup,
destinations, naming, formulas, consent-control collisions, lifecycle, invisible/control Unicode,
noncanonical whitespace, confusable names, and corrupted `{{reference}}` text. Resolve active reachability from configured roots rather than raw
reference counts, including built-ins and recursive tag/trigger/variable cycles.
Inspect tag schedules and firing options, setup/teardown shape and cycles,
malformed trigger groups, Zone boundaries/type restrictions, and consent enum
shape. Every locked module records findings or a source-counted zero result.
For a missing setup/teardown name, rank existing tags by normalized identity, peer use, compatible type, and proximity; remap a unique peer-supported `tagName`, never clear the edge by default, and otherwise retain one precise owner decision.
Normalize payload signatures separately from routing, consent, sequencing,
schedule, priority, pause, and firing controls so control differences cannot
hide behavior-equivalent payloads. Queue same event/destination contracts with
different visible consent controls for explicit review.
When a one-member trigger group participates in another group or cycle, resolve
that dependency before remapping consumers; never present a naive flatten as a
safe action. Treat malformed scalar group members as invalid edges while still
showing any value collision with a valid member.
When exact custom-event sets prove a blocker can never intersect any firing route, remove that blocker edge exactly and delete the trigger in the same operation only if the removal leaves it with no exported consumer. A label-only `(UA)` trigger used exclusively by current GA4 tags receives a collision-free metadata rename; mixed, unknown, or colliding cases remain review candidates.

Never delete or consolidate from a signature alone. Select canonical objects,
all consumer remaps, and non-canonical deletions explicitly. A deletion of any
consumed object is invalid until the accepted operations cover every surviving
consumer remap; consumers deleted by the same operation set are the only
exception. Remaps stay within one supported GTM layer, cannot target a deleted
object, and cannot create a dependency cycle. The complete accepted operation
set must also leave every object name unique within its layer.

A deterministic structural defect whose safe target is established by the export cannot be dismissed as
`not_applicable`, `keep`, an owner question, or a container-evidence limit. Convert it into an exact
operation, or preserve a `documented_exception` already declared in the locked intake context for that
finding/signature/object. A source-proven lifecycle or organisation condition whose safe outcome depends
on rollback retention, vendor ownership, or the final folder taxonomy is a `business_decision`: preserve
its exact condition, owner question, and recommended target rather than inventing a deletion or folder map.
A generated review candidate is not yet a defect: retain it only with the locked `review_candidate` class,
source-specific proof of the intentional distinction, and a concrete recommendation. Use
  `owner_decision_needed` only for a locked review candidate or true business choice, never instead of
  proposing the source-visible fix. Preserve the owner's reason.
### 3. Run Configuration Correctness Independently

Complete every object in `audit-package/configuration_review.json`.
The semantic object set is tags, triggers, custom variables, Zones, custom
templates, clients, Google tag configurations, and transformations. Folders
and enabled built-ins remain operational objects; built-ins also appear as
terminal-source candidates in recursive traces.

- Explain literal purpose, execution, inputs, terminal sources, output/side
  effect, consumers, consent, sequence, and correctness.
- Cite the generated source paths allowed for each semantic statement. A valid
  path citation does not rescue generic prose; the statement must also name the
  source-derived event, path, trigger, variable, value, destination, or output.
- Review every source-owned exported logic leaf exactly once globally by source
  path and value hash. Cross-object execution, consumer, and destination-peer
  leaves remain citeable D3/contract context under their owning object; never
  clone them into each consumer's local branch ledger.
  Review rows, branch paths, D3 keys, contract topics, technical findings, and
  recursive trace identities are also exact-once sets: duplicate, blank, or
  malformed entries fail instead of being overwritten during indexing.
- Preserve empty objects and arrays as explicit leaves. For tags, groups, and
  Zones, resolve referenced trigger conditions recursively, including missing,
  ambiguous, and cyclic targets. For sequenced tags, expose target status and
  execution controls. For variables and other dependencies, expose the
  downstream consumer fields needed to judge the consumer contract; D3 may not
  stop at the source object's own fields.
- Recursively trace every referenced variable to its terminal data source,
  including nested variables, dataLayer paths, built-ins, constants, lookup
  tables, URL/cookie/DOM sources, custom code, missing references, and cycles.
  When a missing name has exactly one existing case-preserving
  Unicode/whitespace-normalized match, the target is source-known: propose the
  exact field repair and preserve all surrounding formula, trigger, routing,
  consent, and payload settings. Ambiguous or semantic name matches remain
  owner decisions.
  For lookup/regex tables, validate row shape, unique matches, regex syntax, ordering/shadowing, blank semantics, and enabled defaults.
  When one name resolves to multiple custom or built-in candidates, retain every
  candidate and mark the terminal ambiguous; never select the first/last match.
  Preserve consumer event/destination contexts and same-destination peer
  configuration—including peer type/absence, server endpoint, consent, route,
  and execution controls—so a source object is judged against the route that
  consumes it, not merely against its own local fields. A shared destination
  creates an inheritance-review obligation; it does not prove inheritance.
- Review every nonblank executable custom-code line in concrete behavior blocks.
  For community templates, extract sandboxed JavaScript sections separately;
  do not count terms, metadata, parameter help, permissions, tests, licenses, or
  comments as executable lines. Review permissions through the template/vendor
  contract instead. Resolve every parser, security, side-effect, and maintainability signal, including dataLayer resets,
  internal `google_tag_manager` access, manual `gtag`, debugger statements, literal cookie attributes, and listener cleanup/once/guards.
  If the optional AST parser is unavailable or cannot parse the code, record a
  mandatory parser-coverage limit. It may be bounded only by an explicit
  line-by-line substitute review that attests every exported code-segment hash
  exactly once and describes the identifiers, endpoint, output, and side
  effects of each individual segment; never claim AST coverage through a
  generic block-level fallback. Preserve the positive polarity of every
  source-visible send, request, script/DOM effect, dataLayer/storage action,
  listener, read, and return; correct tokens wrapped in a denial do not pass.
  Separate advisory review signals from deterministic defects. Inline scripts,
  code size, DOM/storage/global access, script creation, and guarded listeners
  are prompts to inspect the complete code and consumer route; their presence
  alone never creates an owner question. Close a source-present but acceptable
  advisory pattern as `No defect after review`, with source-bound rationale.
  Deterministic defects and genuine evidence boundaries remain action,
  exception, or owner obligations. Never dismiss a source-present pattern as a
  false positive. A cleanup opportunity requires `proposed_action`, a
  documented exception requires `exception_basis`, and an owner decision
  requires a source-specific interrogative `owner_question` plus the analyst's concrete
  `recommended_action`; a verdict alias alone fails. A confirmed issue links by
  `technical_finding_keys` to exactly one concrete defect and an exact cleanup operation.
  A parser may normalize `{{GTM variable}}` substitutions solely to recover a
  structural parse, but it must disclose that normalization and must not infer
  the substituted value's runtime type.
  Treat a custom-template resource whose executable implementation is absent
  from the export as opaque. Review its visible metadata and permissions, but
  require an owner/evidence boundary instead of inferring executable behavior.
- For vendor objects, use the bundled official source first. When absent or
  stale, search the internet for current official vendor documentation, add the
  verified vendor/domain/source to the versioned registry, validate it, and
  rebuild the review before certification. Create one canonical identification
  task per unknown host/template identity and link its other objects and
  contract topics through the generated research dependency key. An
  unregistered source is not
  self-authenticating because its hostname resembles an analyst-entered vendor
  name. Until registry validation and rebuild, the topic remains `Unproven`. An
  unknown external host, script, or template creates a mandatory vendor-
  identification and official-source research contract; never silently leave
  it unclassified.
  Record the current official-source search in `research_status` before an
  owner/evidence fallback; `not visible in the export` is not a research attempt.
  Preserve all vendor matches for mixed Custom HTML and create a separate
  research obligation for each unmatched external host.
  Derive host/vendor obligations only from behavior-bearing configuration:
  export/UI metadata such as `tagManagerUrl`, path, notes, and workspace IDs is
  not integration evidence. Keep an explicit recognized server-transport host
  in the server-routing contract rather than relabeling it an unknown vendor.
  Generated contract topics carry a locked deterministic state: a visible
  unsupported or missing required value is Non-compliant; a dynamic or unseen
  runtime value is Unproven; only a genuinely inapplicable topic is Not
  applicable. Do not use Not applicable as a fallback. Apply versioned vendor event status, required fields,
  type/length rules, endpoint, consent, routing, and deduplication contracts without guessing migrations.
- Treat current Google analytics events as GA4 unless the export proves a
  Universal Analytics exception. Check official event names and official
  ecommerce dataLayer/item contracts before proposing custom JavaScript.
  A `(UA)`/Universal Analytics name alone is only a candidate: trace consumers and never migrate a current GA4 dependency from its label.
- Always check transaction ID, currency, revenue/value, total price, quantity,
  item arrays, product IDs/categories/prices, lead values, consent states, and
  all standard/frequently consumed business variables when present.
  A GA4 `purchase` without exported `transaction_id` configuration cannot be
  marked contract-compliant; uniqueness remains a separately assessed source
  and runtime contract. A `refund` must assess linkage to the purchase ID.
- Resolve source-derived formula signals such as fixed numbered slots,
  aggregation operators, fallbacks, and output shape. A formula such as
  `price1 + price2 + price3` cannot be dismissed generically: prove the business
  rule and cardinality or record a defect/owner decision.
- Evaluate the complete effective consent route: native consent settings,
  additional checks, firing and blocking triggers, consent variables,
  sequencing, and browser-to-server routing visible in the export. Treat a
  server-enforced transport contract as valid client-side architecture when
  the export proves that the transport route forwards the required consent
  state consistently. In that pattern, transporter tags may fire without
  client blocking; do not flag the missing blocker itself. Verify the forwarded
  variable/parameter chain, purpose coverage, timing, route coverage, and any
  direct browser vendor paths. State that unseen server enforcement is outside
  the web-container audit without turning that boundary into a defect.
  A consent-looking object/event name or an arbitrary blocker is candidate
  evidence, not proof of control or forwarding. Forwarded consent facts require
  an exported server route plus a behavior-bearing payload/settings chain.
  Preserve every matched vendor on mixed code when deciding media review.

For every object, complete all generated D3 cross-checks exactly once:
purpose/output, execution/scope, input/output/consumer, and consent/sequence;
also complete code-behavior and official-vendor-contract alignment whenever
generated. Each conclusion must cite only its generated object-specific source
anchors and name every deterministic obligation that controls it. The same
Issue/Unclear state must propagate through branch, D3, overall verdict, defect,
and applicable official-contract topic; every failed check links to a concrete
defect.
Judge container-visible correctness before external proof limits: runtime-only uncertainty uses explicit handoff fields and never erases a visible Issue. Confirmed code issues link to one defect and operation unless fully excepted/owner-bound; identical code needs one disposition unless cited consumers justify a difference.
A source-proven Issue becomes an exact operation when the valid target state is visible. If an owner must choose the replacement value or route, the Issue may remain owner-bound only when its recommendation names the object, defect ID or exact evidence path, and concrete remediation; generic defect handoffs fail.

Do not stop at a variable name or parameter list. Prove the configured value,
type, timing, and consumer meaning. Do not write generic summaries such as
`outputs a value`, `configuration reviewed`, or `custom code inspected`.
### 4. Run Business Architecture Independently

Complete every family and comparison in
`audit-package/architecture_review.json`.

- Group tags first by configured event/business action, then route,
  destination/vendor, and source-derived scope. Keep singleton families.
- Treat Zones and Google tag configurations as architecture roots. Compare
  Zones governing the same child container and tags/configurations sharing a
  configured destination even when their names and remaining settings differ.
- Traverse each family's firing/blocking triggers, groups, sequencing,
  templates, and recursive variables.
- Preserve unresolved dependency edges in the family chain. Generate explicit
  candidates for trigger-group cycles, differing consent/sequence/server routes
  within the same event/destination contract, and cross-vendor business events
  extracted from recognizable custom-code calls.
- Join Google tag configurations, same-destination Google event tags, and
  same-business-event direct media/browser tags into browser/server comparison
  families when a server route is exported. Review destination inheritance,
  consent, terminal source, payload, and deduplication across the whole family.
- Review every generated exact, near, shared-source, shared-route, shared-destination, event-family,
  custom-code, condition-subset, canonical funnel-step, and behavior-equivalent environment/container variant after metadata is excluded.
- Assess each member's active/paused state, role, necessity, distinguishing
  logic, payload, consent, consumers, and ownership.
- Bind every member and family statement to generated object-specific evidence
  terms. Family-level prose that could describe any container is incomplete.
- Decide exact duplicate, functional overlap, consolidation candidate,
  intentional variant, complementary, conflict, unrelated, owner decision, or
  container-evidence limit.
- Keep is valid only for intentional variants, complementary implementations,
  or unrelated objects and must cite a source-visible distinction for every
  retained member; opaque behavior-signature hashes are not analyst evidence. Owner-decision and container-limit verdicts require their
  matching dispositions; an owner decision also requires one precise question and one concrete
  recommended action.
- Same payload/different route, shared-Zone-child, cyclic trigger-group, and
  browser/server consent/deduplication candidates cannot be retained by a
  generic `Keep`. A source-visible deterministic relationship also cannot be
  hidden wholly inside `Container evidence limit`; decide the visible part and
  reserve the boundary only for the precise unseen fact.
- An actionable relationship verdict is incomplete unless its structured
  operation changes, remaps, creates a replacement for, or deletes at least one
  candidate member's behavior. An unrelated, name-only, no-op, or object/path-
  mismatched edit cannot resolve the relationship. Consolidation names a
  canonical relationship member and removes a non-canonical member.
- Only after exact configuration equivalence is proven, recommend a source-ranked canonical default: active, then more-consumed, then non-copy/legacy/test name, with object key only as final tie-breaker; consumer count never proves equivalence. Remap all surviving consumers before deletion.
  Exact equivalence leaves no distinct business behavior to choose: emit the
  consolidation operation now and leave approval to the normal operation gate;
  do not create an owner question merely to select between identical copies.
- Unsafe owner questions identify at least two candidate objects and put the
  actual route, Zone scope, trigger cycle, or browser/server consent-and-
  deduplication decision inside the interrogative clause. For browser/server rows,
  absent or unseen runtime deduplication and end-to-end consent parity must be
  stated with negative/unproven polarity; text cannot turn missing evidence into
  a positive complete, guaranteed, identical, synchronized, verified,
  equivalent, or consistent claim.
- Define the simplest target architecture that preserves required business,
  market, product, consent, route, and vendor differences.
- Perform an open relationship-discovery pass after reviewing generated
  candidates. Search every source object through semantic name/business
  variants, normalized route/condition overlap, terminal-source/formula
  overlap, consumer/destination/event overlap, consent/sequence/server-route
  conflicts, and funnel/question/market/product families. Add `DISC-*`
  comparisons for new candidates, declare at least one mapped comparison type
  plus the exact suitable locked discovery method(s) that found each row, list
  that row under those method reviews, and account for
  every source object in the discovery attestation. A discovered row declaring
  an unsafe type, or using a subset/superset of a deterministic unsafe
  candidate, inherits the same mandatory methods, retention policy, and caution
  states; `DISC-*` is not a fallback around generated rules. Distinguishing
  evidence excludes raw/truncated code, placeholders, malformed states, and
  generic lexical noise.

The generated discovery-method coverage, candidate lists, all-object scope,
and source-scope hashes are locked facts. Complete each method review against
that exact scope; do not replace it with a subjective checklist or a generic
`no overlap found` statement.
When no additional relationship is found, the zero-discovery rationale must
name every locked discovery method and source-specific object facts.

Generated candidates are a minimum obligation set, not a closed world. Names
and similarity scores create review obligations, never findings; consolidation
requires configuration and business-equivalence proof.
### 5. Validate, Reconcile, And Simulate

```bash
python -B scripts/gtm_operational_review.py validate container.json audit-package/operational_review.json
python -B scripts/gtm_configuration_review.py validate container.json audit-package/configuration_review.json
python -B scripts/gtm_architecture_review.py validate container.json audit-package/architecture_review.json
python -B scripts/gtm_operation_compile.py container.json audit-package/operational_review.json audit-package/configuration_review.json audit-package/architecture_review.json reconciled_operations.json --route "Pending user selection" --pretty
python -B scripts/gtm_future_state_check.py container.json reconciled_operations.json --output future_state_gate.json --pretty
python -B scripts/gtm_three_run_gate.py container.json audit-package --operations reconciled_operations.json --pretty
```

Block delivery when a run is incomplete, runs contradict, one operation key contains different
mutations, a consolidation lacks architecture agreement, or simulation creates a broken reference,
new sanitation/configuration issue, or relationship not covered by an architecture-backed operation.
For a non-unsafe discovery-only relationship revealed by an approved source repair, an explicit Run-3
retention decision covering every candidate pair is equivalent evidence; do not invent a no-op mutation.
Also block behavior-changing additions, edits, remaps, or deletions when the
affected architecture family/comparison is preserved or unresolved. Metadata-
only names, notes, export URLs, and folder moves remain outside that behavior
rule but still require their own approved operation. Deleting an object that
Run 1 proves is unused, reachable only through paused tags deleted in the same
operation, or itself paused is outside the active-behavior alignment rule;
reference coverage and future-state simulation still apply.
An exact, source-bound non-destructive repair from Run 1 or Run 2 may use
completed Run-3 family coverage instead of duplicating the same field mutation
inside an architecture row. It may not create, delete, or remap objects, and
must still pass the future-state gate; the narrow exception is deletion of a trigger made orphan by the same exact, provably impossible blocker-edge repair. A Run-3 cleanup operation takes
precedence over weaker candidate rows only when its complete structured
mutation is the same; no unrelated operation can borrow that cover.
Merge independently worded operations only when their structured mutations are
identical; deletion rationale and a displayed canonical label are explanatory,
while endpoints and field mutations remain structural. Retain each lens's
rationale and source reference in the packet.
Compose generated text repairs only when they share the same object, normalized field path, and before value; unrelated fields remain separately approvable.
The same exact mutation compiles once with every lens rationale; wording never merges different mutations, and an `unused` label cannot bypass required architecture alignment.

Structured operations create, add, change, remap, rename, or delete. Recommend the best safe future
state once; explicit operation approval controls execution, so never weaken or defer recommendations.

The compiled packet has one decision-ledger entry per finding, object, family,
and comparison; every cleanup disposition becomes one exact operation. Report
projected object counts and every measurement family's target state, operation links, preserved behavior,
consent/routing, and evidence-based priority dimensions. Container-only evidence
limits remain source-linked audit boundaries; they are not runtime-test tasks.
Do not create a Preview, browser, CMP, network, vendor, or other runtime-QA
handoff in this skill. If the analyst later wants external acceptance work,
they invoke `gtm-preview-recette` as a separate scoped task. Project
organisation only from exact operations or policy decisions—never invented
moves or quotas. Action completeness rejects deterministic operational fallback
and vague configuration Issue handoffs; every genuine owner/evidence decision
retains one exact recommendation.
When several runs raise the same complete object-set decision, retain every
source judgment in the ledger but show one authoritative architecture decision
or operation. When an exact Unicode/whitespace-only reference repair fixes an
upstream variable, resolve dependent consumer questions to that same operation
instead of asking the owner again.

Use the shard manifest to resume large runs. A missing, duplicated, pending, or
source-mismatched shard makes the corresponding run incomplete.
### 6. Build The Cleanup Plan

```bash
python -B scripts/gtm_human_rows.py reconciled_operations.json human_rows.json --pretty
python -B scripts/gtm_workbook_build.py audit-package reconciled_operations.json human_rows.json cleanup_plan.xlsx
python -B scripts/gtm_audit_gate_check.py cleanup_plan.xlsx --operations reconciled_operations.json --pretty
python -B scripts/gtm_privacy_scan.py cleanup_plan.xlsx
```

The workbook has at most eight tabs. Cleanup Plan has the canonical seven columns, including one filterable general problem category before the exact area/problem type; every other tab has six or fewer columns. Only Summary and Cleanup Plan are visible.
Hidden proof is privacy-scanned, and the audit package retains exhaustive proof. Show every operation and owner decision; summarize nonblocking container-evidence limits once while retaining exact hidden proof. Do not add runtime-QA tasks.
Scope owner blocks to listed objects. Homogeneous duplicate, unused, naming, or folder work may share one presentation row only when every atomic ID, action, object, approval choice, and QA remains explicit.
Use `layer:ID — Name` consistently and omit batch-count boilerplate for a single owner decision.
Do not include a change log.
Order the visible plan by impact without changing canonical obligation or execution order. Use concrete analyst language—`Problem`, `Change`, preserved settings/measurement, priority, approval, static verification, and rollback—rather than concatenated machine fields such as `Root problem / Business impact / Preserved business behavior`. For invisible Unicode, explicitly say that the reference contains a non-breaking or non-standard space, show the readable intended `{{Variable}}` name, and explain that GTM matches names exactly. Summarize source-confirmed retained business families as well as cleanup operations.
If action completeness is not `pass`, render only one visible `BLOCKED-001` draft row plus accurate Summary counts; never present a partial plan for approval.
### 7. Offer The Next Action

After audit/plan delivery, ask whether the user wants:

- direct GTM/API/MCP cleanup; or
- an importable GTM container JSON.

Ask which operation IDs are approved; a subset remains an incomplete staged cleanup and must be re-simulated. Do not ask for an aggressiveness mode. Direct cleanup must use
a new workspace, modify existing objects when possible, preserve readable GTM View Changes, and warn
if workspace quota blocks creation. JSON must be a valid GTM import artifact, not Markdown; import
behavior may recreate objects and is less suitable for per-element review.

Naming standardization is mandatory during approved cleanup unless excluded.
Apply it after behavior, canonical objects, remaps, and deletions are settled. Prefer an explicit user convention; otherwise normalize the dominant local convention without following inconsistent prefixes blindly. Preserve meaningful vendor acronyms, distinguish trigger groups with `TG`, avoid redundant `TR`, standardize case, and keep names unique within each GTM layer.

### 8. Execute Safely And Log Separately

- Never publish or create a GTM version unless explicitly requested.
- Never mutate without approval, rollback source, and a passing `gtm_execution_guard.py` preflight; enforce exact do-not-touch keys and operation-specific server, activation, and post-observation confirmations.
- Re-read the complete workspace immediately before mutation and stop on source-identity drift.
- Preserve custom-code variable references and exact values; never replace them
  with unrelated literals.
- Validate/read back every batch and stop on drift, missing references, consent uncertainty, or
  unexpected recreation. After final readback, reassess all three lenses against the approved state.
- Produce a separate field-level change log linked only by exact
  layer/ID/path/before/after. Certify execution only when complete readback
  matches the approved simulation with no unlinked change. Label simulations.

End every stage with one concrete next step.

## Rule Routing

| Need | Reference |
| --- | --- |
| Three-run workflow and gates | `references/03-rules/execution-contract.md` |
| Operational modules | `references/03-rules/operational-sanitation.md` |
| Object, variable, code, and vendor review | `references/03-rules/configuration-correctness.md` |
| Families, overlaps, and target architecture | `references/03-rules/business-architecture.md` |
| GA4, ecommerce, media, consent, server contracts | `references/03-rules/domain-contracts.md` |
| Naming | `references/03-rules/naming-standardization.md` |
| Operations and mutation | `references/03-rules/operation-schema.md`, `references/03-rules/mutation-playbook.md` |
| Workbook and change log | `references/03-rules/workbook-architecture.md`, `references/03-rules/change-log-template.md` |
| Commands | `references/02-commands/validation-commands.md` |

## Portability

The reasoning contract works with Codex, Claude Code, Gemini, and comparable agents. Python 3.11+ supplies deterministic scaffolds and gates; `openpyxl` builds XLSX and optional `esprima` enriches JavaScript facts. Missing tooling blocks the full audit when source locks, obligation coverage, reconciliation, or delivery gates cannot be reproduced. State the prerequisite and stop; never create a reduced fallback mode.
