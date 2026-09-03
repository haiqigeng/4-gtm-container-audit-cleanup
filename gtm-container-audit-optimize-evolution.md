# GTM Container Audit & Optimize — Evolution Record

## Status And Authority

This document records the current single-pass product decisions and historical
release changes. It is an evolution record, not a second runtime contract.

The authoritative implementation sources are:

- `SKILL.md` for activation, workflow, and hard boundaries;
- `references/03-rules/audit-coverage.md` for the North Star and all audit areas;
- `references/03-rules/workflow-and-assurance.md` for independence, reconciliation,
  and deterministic target validation;
- `references/03-rules/domain-contracts.md` for current GTM, Google, CMP, vendor,
  and client-side transport criteria;
- `references/03-rules/workbook-delivery.md` for the human delivery contract.

If this record and an authoritative source ever differ, the authoritative source
wins and this record must be corrected before release.

## Active Development Goal — Final Qualification And Release Addendum

Approved by the user on 2026-09-03. This extends the active development goal's
completion criteria; it does not change the skill's North Star or runtime
workflow. It supersedes the earlier restriction on Git push and release
publication only. GTM mutation and local skill installation remain outside this
authorization.

After completing the existing improvement, four-pair evaluation, correction and
regression work, perform one final independent release-candidate evaluation:

1. Evaluate product design, practical audit/optimisation utility, and technical
   health against all seven project `AGENTS.md` rules and the authoritative skill
   documents referenced above. Assess simplicity, fitness for the agreed scope,
   coverage, appropriate findings, independence, maintainability, dependencies,
   reliability and human delivery. Support the verdict with observed evidence;
   distinguish unresolved defects from evidence limits and optional enhancements.
2. Review instruction quality using positive guidance first and negative
   guardrails second. Prefer concise instructions describing the desired action,
   decision criteria and result. Replace redundant or lengthy prohibition lists
   when positive guidance preserves their intent more clearly. Retain concise
   negative guardrails where they materially prevent unsafe actions, unsupported
   claims, scope expansion or loss of audit independence. Apply this editorial
   principle without weakening coverage or changing the product contract.
3. Correct material findings at the owning component and rerun affected checks
   and dependants. Then check internal coherence across activation, North Star,
   scope, audit criteria, workflow, scripts, schemas, tests, workbook, examples and
   documentation. Qualify the final corrected candidate, not an earlier build.
   Do not claim universal optimality or zero possible future defects.
4. Once the existing release criteria and this final evaluation pass, publish a
   new version from the repository's `main` branch. Inspect the remote and existing
   release history to select the next appropriate version. Update all applicable
   repository surfaces to accurately describe the released skill, including
   README, skill/package/version metadata, documentation, examples, release notes,
   distribution assets and repository About/description/topics/links where used.
   Preserve accurate historical release records. Keep `main` as the sole branch;
   do not introduce an auxiliary release branch.
5. Verify that the remote `main`, release tag, published release and assets match
   the qualified version, and that repository-facing information is current.
   Report the version, commit, release link, evaluation evidence and any genuine
   remaining limitations. Publication is part of completion, not merely a local
   commit or prepared release draft. Report an actual access blocker rather than
   claiming publication succeeded.

This is a development/release gate, not additional machinery required during a
normal container audit. Reuse valid evidence and resume the earliest affected
step after a fix; keep the existing production single-pass workflow intact.

## Decided North Star

Make an existing GTM container as clean, correct, simple, and maintainable as if
a senior web analyst had configured it today from an empty container for the same
proven needs. Using only container-visible evidence, identify what is wrong, what
can be improved, and what should stay, then turn every justified improvement into
an exact, safe target state and deliver it in one trustworthy analyst workbook.

Apply that standard at four connected levels:

1. individual object;
2. complete implementation chain;
3. business, destination, or vendor family; and
4. whole-container architecture.

The audit is not only a defect finder. It must distinguish:

- `defect`;
- `correct_but_materially_non_optimal`;
- `justified_as_is`;
- `owner_decision`;
- `container_evidence_limit`; and
- source-proven `not_applicable`.

A candidate is never a verdict. Repetition alone is never enough to recommend
consolidation. Every recommendation must preserve all proven timing, value, type,
consent, route, destination, scope, and ownership distinctions.

One execution has one comprehensive source scan and assurance, two complete
independent semantic audits in parallel, one reconciliation, deterministic
validation of their combined recommendations, and one verified workbook. Source-
visible consequential cleanup and coherent target design belong in the initial
audits. No simulated-target semantic review cycle or convergence gate is part
of the product. A static validation pass does not establish runtime behaviour or
guarantee that no further optimisation could be found.

Source-known field repairs constrain retained objects, not redundant intermediate
states. A proposal may combine the exact repair with other justified actions, or
explicitly retire that same object instead. Retirement keeps the normal semantic,
consumer, dependency, and neutral-review checks. Each action has one operation
owner; do not edit a field and delete its object in the same target.

Workbook redaction follows GTM's parameter representation as well as ordinary
sensitive dictionary keys. It redacts sensitive parameter payloads and sibling
name/value-table values before they enter visible rows or technical comments,
while preserving names, ordering, object identities, and canonical action hashes.
This presentation correction does not change source evidence or audit judgments.

Initial operation validation now always simulates the complete proposed packet;
it no longer does so only when protected objects are declared. Implicit consumer
rewrites from renames/remaps must respect source-bound field-change ordering.
Before-value drift names the exact failed operation. Repair the affected authored
dependencies and dependent reconciliation records, retaining all unaffected work.

Trigger remaps update structured trigger-group membership as well as tag firing
and blocking lists. They do not replace matching quoted IDs in unrelated text.
This corrects simulation of already-authored consumer remaps; source decisions
and intended targets remain unchanged. Combined-target graph validation remains
the gate for newly broken references.

Delivery now maps the class-specific audit schema directly. Retained decisions
use their assessed reason and existing no-change meaning; owner decisions use
their authored next step, not an optional recommendation target. Evidence limits
remain visible. Overview summaries use populated class-specific assessments.
Missing required semantics still reopen the owning record; optional blanks do
not justify invented findings or repeated source audits.
The delivery name index combines source and target names without mutating the
canonical source directory in memory; repeated mapping yields the same result.
Recommendation scope includes the complete declared operation and explicit
consumer remaps, not just the narrower object that owns its audit finding.
Reconciliation no longer treats equal verdict labels with empty optional targets
as proof of semantic agreement. Differing canonical content is routed through
the existing neutral review; already-required reviews retain their reasons and
can be reused when their complete inputs remain identical. Selected assessments
and operation references must form one coherent target before delivery.

## Current Phase Boundary

The v2 workflow accepts one complete GTM **web-container** export or equivalent
read-only evidence and ends at one validated analyst workbook.

It does not:

- audit a server container, accept a server-container export, or model
  server-container Clients, Transformations, or templates;
- run GTM Preview, browser, network, data-layer, cookie, or CMP runtime checks;
- design missing measurement requirements or a tracking plan;
- decide legal compliance;
- mutate GTM, create or apply an import, create a version, or publish;
- certify post-change state;
- create an execution approval packet, change log, or audit-to-audit delta.

The web container's client-to-server transport and consent-forwarding contract is
in scope. Downstream server-container claiming, transformations, consent gating,
vendor requests, responses, and receipt remain outside the evidence.

## Decided Consent And Routing Architecture

Classify the route before judging the tag:

| Route | Positive trigger | Consent owner |
| --- | --- | --- |
| Consent infrastructure | Consent Initialization or the documented CMP default/update event | The consent writer; never a vendor gate |
| Confirmed Advanced Consent Mode | Normal lifecycle or business event without a granted-state condition | Coherent defaults and updates plus intrinsic product behaviour |
| Pure client-to-server transporter | Normal lifecycle or business event without a granted-state condition | One complete shared consent value forwarded to route hosts with explicitly approved downstream consent-gating ownership |
| Direct browser/vendor route | Consent-free CMP timing event for page-load work, otherwise the real business event | One reusable vendor, purpose, or category denial blocker |

For every direct non-Advanced route, including Google tags:

- the positive trigger never carries the granted-state condition;
- one reusable blocking trigger owns consent eligibility;
- absent, unknown, or denied state fails closed;
- consent is not duplicated between the positive trigger and blocker;
- Additional Consent Checks are not used as the configurable gate; and
- Built-In Consent Checks are recorded only as intrinsic template metadata.

For a pure client-to-server transporter:

- use firing triggers only;
- use no client consent gate or consent blocker;
- configure one complete canonical consent value once and inherit it for every
  transported event; and
- require locked approved context naming every route host as having a downstream
  server consent-gating owner before removing any client gate; and
- treat a direct browser-vendor bypass as a mixed route, judged separately under
  the direct-route rule.

## Final Scan And Audit List

### 1. Source Identity And Evidence Completeness

Verify account/container/version or workspace identity, WEB type, export shape,
every supported layer, duplicate IDs, malformed structures, and omitted-layer
meaning. Block partial, ambiguous, or unmodelled evidence.

### 2. Object Inventory And Identity

Inventory every object, key, ID, exact and normalised name, type, status, folder,
note, template/version metadata, role, vendor, destination, purpose, route, and
owner. Do not infer obsolescence from an unclear name.

### 3. Dependency And Reference Graph

Recursively resolve variables, triggers, blockers, trigger groups, sequencing,
folders, templates, Zones, settings, destinations, and every web-container value
path. Detect cycles, missing references, ambiguous targets, and all consumers
that must be remapped before retirement.

### 4. Lifecycle, Reachability, And Usage

Assess active, paused, unused, paused-only, sequence-only, scheduled,
environment-limited, rollback, and remnant objects. Recompute reachability after
every proposed target change; never delete from age, pause, or disuse alone.

### 5. Exact Duplicates And Functional Overlap

Compare names, configuration signatures, code, sources, payloads, routes,
loaders, page views, consent writers, and subset triggers. Distinguish duplicate,
overlap, conflict, intentional variant, migration pair, and insufficient evidence.

### 6. Tag And Template Configuration

Check template identity, version, publisher, permissions, IDs, required fields,
parameter shape, deprecated settings, and multi-vendor behaviour. Prefer native
GTM, then a reviewed maintained template, before equivalent custom code.

### 7. Trigger Event And Condition Topology

Model firing triggers as OR, conditions within a trigger as AND, and blockers as
eligibility suppression. Audit events, filters, regexes, overlap, contradictions,
trigger groups, lifecycle timing, SPA/history behaviour, and data availability.

### 8. Firing Options, Priority, Scheduling, And Sequencing

Inspect explicit priority including `0`, same-event competitors, firing options,
setup/teardown dependencies, cycles, and schedules. Remove explicit zero and
unsupported priority; retain nonzero priority only for a proven same-event start
order. Priority never proves asynchronous completion.

### 9. CMP And Consent Infrastructure

Identify CMP/version, documented events and variables, consent defaults/updates,
Consent Initialization, consent types, duplicate writers, unknown-state handling,
and ordering. Keep readiness/timing separate from vendor eligibility.

### 10. Direct Client-Side Consent Architecture

For every direct vendor route, inspect positive trigger, consent conditions,
blocker, CMP source, exact token matching, Additional/Built-In checks, repetition,
firing option, and later-grant behaviour. Enforce the direct non-Advanced blocker
architecture without vendor exceptions.

For page-load routes, assess whether the configured CMP lifecycle/update event
provides a later-grant firing opportunity or whether an approved reload dependency
is explicit. If neither is established, retain an owner decision or evidence
limit; never move granted-state consent into the positive trigger.

### 11. Advanced Consent Mode

Inspect Google destinations, default/update writers, consent types, timing,
intrinsic checks, blockers, and route. Classify Advanced only from explicit
approved context plus coherent visible configuration; native capability alone is
not proof.

### 12. Client-To-Server Transporter Architecture

Inspect transport URL ownership, direct bypasses, canonical consent source,
forwarding field, inline copies, client gates, destinations, event IDs, and
browser/server overlap. A pure route uses firing only and one inherited consent
value after approved context confirms downstream consent-gating ownership for
every route host; otherwise client-gate removal remains blocked.

### 13. Client-Side Server Handoff And Evidence Boundary

Reconcile every web-container transport host, destination, event identifier,
consent-forwarding field, settings owner, and mixed-route branch. Report whether
the client handoff is aligned and state that downstream enforcement is unseen.
Never request or inspect a server-container export in v2.2.0.

### 14. Variable Graph And Source Contracts

Resolve terminal source, type, data-layer path, defaults, lookups, regex rows,
Custom JavaScript, duplicate sources, and consumers. Prefer the simplest
compatible mechanism and reject unsafe defaults, type drift, and needless
one-consumer indirection.

### 15. Effective Google Configuration And Field Ownership

Resolve every effective value and provenance across Google tags, `gtagConfig`,
Configuration Settings, Event Settings, inherited values, local event tags, and
overrides. Put configuration-wide values with one configuration owner, genuinely
shared event values with one Event Settings owner, and event-specific values
locally.

### 16. Destination, Loader, And Page-View Ownership

Inventory destination IDs, loaders/config tags, automatic and manual page views,
history views, linker settings, routes, and market/product/environment scope.
Establish one deliberate owner per destination and route while preserving proven
multi-destination distinctions.

### 17. GA4 Event And Parameter Correctness

Classify automatic, recommended, enhanced-measurement, and custom events. Check
name spelling/case/reservation, parameters, inheritance, count/type limits, user
properties, debug fields, destination, and page-view ownership without inferring
property-side behaviour.

### 18. Ecommerce

Inspect ecommerce event set, `items`, item fields, transaction ID, value/currency,
tax, shipping, coupon, quantity, refund linkage, duplicate routes, legacy shape,
fixed product slots, and deduplication fields. Do not invent defaults or claim
runtime uniqueness.

### 19. Ads, Floodlight, And Other Vendor Tags

Audit loaders/actions, IDs/labels, values, products, matching data, deduplication
keys, route, template, scripts, and deprecated fields against a current official
or installed-template contract. Unknown integrations remain blocked evidence
limits.

### 20. Source-To-Destination Value Semantics

Trace values through variables, lookup or code-based mappings, settings,
overrides, payloads, and destinations, preserving type, cardinality, null, empty,
zero, false, array, and object meaning. Prefer fixing the source over keeping
compensating mappings. Do not inspect server-container Transformation objects.

### 21. First-Party Data, Identity, And Privacy-Sensitive Fields

Inventory user IDs, user properties, `user_data`, enhanced conversions, matching
data, hashes, PII-like fields/URLs, DOM selectors, secrets, and debug exposure.
Prevent raw PII and double hashing while leaving legal/policy decisions external.

### 22. Custom Templates And Custom Code

Inspect template metadata/permissions/domains and every executable code segment,
line range, hash, parser state, global, request, data-layer reset, storage access,
DOM effect, listener, timer, `eval`, callback, and asynchronous path. Opaque code
is an evidence limit. Replacement requires proven value, type, timing, consent,
route, and destination equivalence.

### 23. Zones, Environments, And Portability

Audit Zone boundaries, child containers, restrictions, duplicated duties,
permissions, environments, embedded IDs/hosts, and production defaults. Preserve
meaningful separation and treat unseen child containers as evidence boundaries.

### 24. Naming, Folders, Notes, And Documentation

Find inconsistent, duplicate, ambiguous, malformed, corrupted, or placeholder
names and missing folder/note/owner context. Rename only after canonicalisation;
avoid cosmetic-only operations.

### 25. Static Efficiency And Complexity

Measure object/code volume, duplicate script/listener bodies, large tables,
repeated parameters, fan-out, dependency depth, and one-consumer abstractions.
Reduce independently maintained definitions and failure surfaces without making
runtime-performance claims.

### 26. Business Architecture And Greenfield Target State

Group every object into source-derived families by need, event, vendor,
destination, loader, consent owner, route, source, market, brand, and product;
include singletons and open discovery. Define what a senior analyst would build
from empty for the same proven needs.

### 27. Exact Operations And Deterministic Target Validation

Compile exact creates, additions, changes, named-field removals, remaps, renames,
pauses, deletions, dependencies, verification, and rollback. Simulate the complete
combined target from the locked source and validate references, dependencies,
conflicting writes, protected objects, and implemented consent/routing safeguards.
Recompute target facts and assurance without creating new semantic work.

## Decided Workflow

### Stage 1 — Lock Evidence

Lock the complete web source, context, runtime identity, audit contract, vendor
registry, approved requirements, and exact `do_not_touch` keys. Package creation
must pass source identity and independent scan assurance before semantic review.

### Stage 2 — Canonical Scan And Assurance

Build one deterministic neutral fact layer and typed obligation ledger. In a
separate fresh agent context, reread raw JSON to verify object/reference/variable/
trigger/settings/consent/route/code/vendor/candidate/ownership/branch identities
and exact area coverage. Record its agent/context labels plus locked input/output
hashes. Every inapplicable mechanism needs a source-counted zero.

The scan may create candidates but may not carry a verdict, recommendation,
selected policy, operation requirement, or target hint.

Area 1 closes through this evidence/assurance gate, areas 2–26 through both
semantic audits, and area 27 through operation synthesis and target validation.

### Stages 3 And 4 — Two Complete Independent Audits

Run two complete audits concurrently in separate fresh agent contexts:

- Audit A traverses object and implementation chains first;
- Audit B traverses families and target architecture first.

Both cover every applicable semantic obligation. Each receives its own locked
input bundle and records agent/context labels plus exact input/output hashes. Both
may read the same version-locked skill rules; neither receives the other's work
before both are complete and sealed. Audit B is generated-candidate-blind until
its source-only checkpoint. Both audits seal their source-only checkpoint before
approved requirement evidence is released.

Both audits inspect all consumers and remaining dependencies before recommending
consolidation or removal, and include source-supported consequential cleanup in
the same coherent target. Close shared settings, trigger/blocker ownership,
loader/destination families, naming, and custom-code behaviour before sealing.
Lack of an authored operation is unfinished agent work, not an owner decision.
Separate independently actionable defects from unrelated ownership questions in
the same object or family through existing atomic records and structured open
discovery where needed. Never guess defaults or treat a source-visible missing
guard or global reset as proof of an observed runtime failure.

### Stage 5 — Neutral Reconciliation

Compare atomic decisions by exact obligation, subjects, family, relationship, and
target. Expose agreements, complements, one-sided findings, conflicts, and
different evidence boundaries. Never vote, average, or silently select.

After both audits are sealed, use a separate fresh reconciliation agent for every
disagreement, one-sided finding, and material-risk class. It may confirm, narrow,
reject, or keep blocked; it cannot invent a third actionable target. Record its
agent/context labels and exact locked input/output hashes.

### Stage 6 — Target Synthesis And Deterministic Validation

Compile only reconciled and required-neutral-verified decisions into exact
operations. `scripts/gtm_target_validation.py` reconstructs the combined packet
from sealed reconciliation, simulates it from the locked original, checks the
implemented static invariants, and recomputes the projected facts and assurance.
It introduces no semantic choices, review queues, or new recommendations.

The module exposes `validate_target` and `target_validation_seal_errors`.
Its five artifacts beneath `target-validation/` are `projected-container.json`,
`canonical-scan.json`, `scan-assurance.json`, `validation-proof.json`, and
`validation-seal.json`. Reconstruct saved content from locked predecessors to
reject self-rehashed substitutes. The canonical record binds the verified result
under `target_validation`. A pass covers the implemented static checks only.

### Stage 7 — Human Workbook

Map the sealed canonical record to one human workbook. A missing or incorrect
mandatory delivery field stops delivery. A focused repair names user-authorized
exact decision IDs and a concrete reason. The repair helper validates and copies
the prior package to a new working successor, retaining source locks, scan,
assurance, checkpoints, both complete audits, seals, and histories. It excludes
only generated downstream outputs and leaves the predecessor unchanged.

Exact owning records use the existing fresh-context source-audit amendment
protocol, followed by reconciliation, target synthesis/validation, canonical
sealing, and dependent workbook gates. The complete source audits do not restart.
The helper creates no new scan or judgment and does not automatically carry prior
judgments onto changed evidence. Delivery never patches a sealed semantic record.

The editorial transformation may improve declared prose fields only. Deterministic
workbook build and exact recovery must pass. Fidelity review and workbook-only
reader review run as separate fresh agents with declared locked inputs and exact
input/output hashes; rendered inspection, privacy, and formula-injection checks
must also pass.

## Speed Without Weakening Quality

Speed comes from:

- Audit A and Audit B running in parallel;
- deterministic family shards plus one shared-infrastructure unit;
- one reusable canonical fact layer;
- focused independent assurance of critical identities;
- targeted neutral checks instead of a third full audit;
- hash-bound resume and immutable seals; and
- deterministic workbook generation.

None of those mechanisms may reduce obligation coverage, reviewer independence,
raw evidence, combined target validation, or the static evidence boundary. Audit-result
quality and trustworthiness remain the primary objective; time to result is
secondary.

Separately authorized development work may repeat evaluations and corrections to
improve the skill. Those evaluation repeats do not create a product loop or a
target-discovery stage inside an audit execution.

## Human Workbook Decision Surface

The workbook contains:

- `01 Overview`;
- `02 Recommendations`;
- `03 Decisions Needed`;
- `04 Full Audit`; and
- `05 Custom Code` only when source-applicable.

Every exact operation appears once in Recommendations. Every audit decision has
one disjoint primary owner in Decisions Needed, Custom Code, or Full Audit. The
workbook uses human labels, current situation, consequence or benefit, target,
preserved distinctions, evidence limit, and next step. Internal workflow jargon,
unsupported runtime claims, hidden decision surfaces, and vague advice are not
allowed.

Workbook delivery is not execution approval. An analyst may separately approve
implementation through an authorised GTM configuration workflow.

## v1.13 Capability Disposition

| Capability | v2 disposition |
| --- | --- |
| Source, skill, and context identity | Strengthened through exact source/package/runtime hashes and WEB-only evidence gates |
| Deterministic completeness | Consolidated into one scan, independent raw-source assurance, and one obligation ledger |
| Defect detection | Retained and extended across the 27-area contract |
| Custom code | Strengthened with segment, line, hash, parser, side-effect, and ownership identities |
| Vendor contracts | Consolidated in one dated official-first registry with deterministic research ownership |
| Approved requirements | Adapted as locked evidence withheld until both source-only checkpoints |
| Consent and routing | Strengthened with the four-route model, direct blocker rule, Advanced proof, and pure-transporter inheritance |
| Business architecture | Strengthened with families, singletons, relationship candidates, and greenfield target closure |
| Independent review | Two complete fresh-agent audits plus fresh-agent reconciliation and targeted neutral review |
| Target operations | Retained within the static phase and checked through combined target simulation and deterministic reconstruction |
| Human delivery | Replaced by one canonical technical record and one analyst workbook |
| Three-run workflow and copied dual workbooks | Removed as obsolete |
| GTM mutation/import/version/publication | Deliberately absent from v2 |
| Execution approval, change log, audit delta, and readback certification | Deliberately absent from v2 |

The comparison preserves useful behaviour, not old run names, schemas, scripts,
tabs, or compatibility modes.

## AGENTS.md Alignment

- Obsolete three-run, mutation, legacy workbook, and compatibility paths were
  removed rather than wrapped.
- The product has one complete workflow and one workbook implementation.
- Scanner, assurance, obligation, audit independence, reconciliation, operation,
  target-validation, canonical record, and delivery concerns remain separate modules.
- The existing optional parser and bundled spreadsheet artifact runtime are used;
  no duplicate authoring library was introduced.
- Combined target validation is a single deterministic stage with no semantic
  target-review loop. Focused repair reuses the existing source-audit amendment
  protocol in a validated working copy and rebuilds its dependent outputs.
- The v2 cutover occurred only after a complete scan-to-workbook path passed.

## Historical Release Review And Resolutions

The following sixty-four entries describe past release work, including the former
fixed-point/projection-review design. They are historical notes, not operational
instructions or current guarantees. That design has been superseded by the
single-pass workflow above; no legacy command or execution path is retained.
The former full-workflow successor constructor and repair-evidence injection were
removed. Current focused repair follows Stage 7 above.

1. Three retained analyzer messages still used v1 mutation/approval wording.
   They now refer to evidence lock, static target synthesis, or a separately
   authorised implementation. Narrow release guards prevent those phrases from
   returning.
2. The canonical scan removed obvious verdict fields but still exposed action
   hints, operation requirements, a selected naming policy, and prescriptive
   custom-code summaries. Denylist sanitisation was replaced by explicit positive
   fact schemas for operational, configuration, architecture, and code evidence;
   unknown fields are dropped and the complete scan is also checked for judgment-
   shaped keys.
3. Pure-transporter cleanup could remove a client consent gate while downstream
   enforcement remained unseen. Locked approved context must now name every route
   host as having a downstream consent-gating owner before any removal operation.
   Target synthesis compares the source and projected consent-control topology and
   rejects direct or implicit gate removal when projected route ownership is not
   completely approved.
4. Area ownership was implicit. Area 1 is now explicitly an evidence/assurance
   gate, areas 2–26 own semantic decisions, and area 27 owns operation/fixed-point
   status.
5. The Overview's generic “delta” wording could be confused with the deferred
   audit-to-audit delta product. It now says source-to-target object-count and
   operation summary, with the visible column labelled “Change.”
6. An obsolete v1 capability-disposition reference remained in the runnable
   skill route. It was removed; useful v1.13 capability disposition is
   consolidated only in this non-runtime evolution record.
7. Release validation treated a missing blocklist and unmatched wildcard
   references as empty or ignorable. Both now fail closed and have regression
   tests.
8. The first consent-removal fence resolved direct and settings-variable routes
   but not a destination-linked `gtagConfig` owner. Effective route facts,
   independent assurance, Area 13 applicability, and target safety now resolve
   destination-linked configuration owners as well. Explicit transporter hosts
   are also kept separate from unknown-vendor research ownership.
9. Neutral verification was fragmented across unnecessary infrastructure. One
   fresh reconciliation agent now receives the two sealed audits, resolves every
   required neutral class, and records lightweight hash-bound provenance.
10. A canonical semantic defect could identify its owning record but the sealed
    workflow had no executable repair path. That release used complete same-source
    successor runs. This historical constructor was removed; current repair copies
    validated source audit evidence and amends exact owners before rebuilding
    dependent outputs.
11. In the former cycle design, next-cycle preparation wrote decisions and the
    packet before assurance completed. That release added staged transitions and
    rollback. This is historical behavior of the removed cycle workflow.
12. A tagged release and runtime manifest could accept dirty build provenance.
    Tagged release checks and declared/installed runtime identity now fail unless
    the manifest records a clean source commit.
13. The former projection-review design added two peer-blind fresh review agents
    and fresh reconciliation for changed projected obligations. Those target
    semantic reviews are not part of the current product contract.
14. Fidelity and workbook-only reader checks now use separate fresh agents,
    declared locked inputs, distinct labels, and exact input/output hashes.
15. Pre-canonical audit amendments retain the immutable source checkpoint, use a
    fresh agent context, bind the amended artifact to the current prior audit
    seal, and archive the prior audit and seal only after validation passes.
16. A source checkpoint could be resealed in place, leaving an existing audit
    seal bound to stale provenance. Checkpoints are now immutable after their
    first seal, while the sealed-audit gate independently revalidates checkpoint
    and coverage-release hashes and their bindings to the current audit.
17. A late filesystem failure during amendment could archive history and replace
    the canonical audit before the current seal changed. The complete transition
    is now staged and recoverable; any failed replacement restores prior audit
    and seal bytes, removes partial history, and clears staging.
18. Downstream gates checked only the current audit and seal, so deleted or
    altered predecessor history could go unnoticed. Every sealed-audit check now
    proves exact history counts, contiguous sequences, parent links, archived
    audit hashes, parent bindings, and unchanged checkpoint/release
    provenance through the full chain.
19. A failed predecessor backup could leave a partial staging file that rollback
    mistook for a valid backup. The transaction now records which current targets
    were actually replaced, verifies every backup hash before commit and before
    restoration, and preserves recovery evidence if rollback itself cannot finish.
20. A coverage-release manifest could be rehashed with a false checkpoint-seal
    identity. Audit validation and every sealed-audit gate now require its source-
    checkpoint binding to equal the exact current immutable checkpoint seal.
21. An amendment validated its candidate but did not preflight the already sealed
    predecessor chain. Before staging, the owner-scoped sealed-audit gate now
    revalidates the current audit, complete history, checkpoint, bundle, released
    inputs, and release manifest; stale provenance fails without any audit write.
22. A family-sharded amendment could not pass predecessor preflight after its
    live unit files changed, because the prior audit was revalidated against the
    new shard contents. Every seal now versions the exact work-unit manifest and
    completed shard files it used. Current and historical records validate only
    against their own immutable sequence snapshot, and the recoverable transition
    removes a new snapshot if any later commit step fails.
23. Work-unit merge trusted the same embedded identity digest copied into the
    manifest instead of recomputing an immutable contract, so forged audit,
    source, ledger, or family fields could reach a seal. Unit identity now has an
    explicit immutable-field projection, and both merge and final validation
    recompute it and prove exact manifest and decision membership.
24. A sealed sequence directory could be replaced by an NTFS junction to an
    external copy while preserving content hashes. Snapshot generation, commit,
    history inventory, and final validation now reject symlinks and Windows
    reparse points, prove every resolved parent boundary, and enumerate only
    self-contained regular trees.
25. A forged post-merge audit could change one decision and recompute every hash
    stored inside that same mutable audit while leaving its sealed shard evidence
    unchanged. Final work-unit validation now deterministically reconstructs all
    decisions and discoveries from every declared unit and requires exact equality
    with both initial and amended audit artifacts.
26. The retained naming reference still required a v1.13 cleanup-plan row and
    hidden rename/proof tabs, conflicting with the v2 workbook contract. Naming
    now resolves through its canonical semantic decision, one visible
    Recommendations row per actionable operation, and row-bound comments; hidden
    decision surfaces are explicitly prohibited.
27. Explicit work-unit identity projections correctly separated immutable and
    authored fields but could otherwise ignore an undeclared top-level context
    field. Manifest, manifest-record, and unit schemas are now closed, so foreign
    or judgment-bearing context cannot be added without blocking merge and seal.
28. A pre-existing `audit-seals/history` NTFS junction could redirect amendment
    history writes outside the package and later be accepted as local provenance.
    Seal, history, snapshot, bundle, candidate-audit, and canonical-audit paths
    now prove direct regular parentage before staging, reading, or writing.
29. Nested work-unit decisions and completion records were filtered into maps,
    allowing non-object or duplicate proof rows to survive beside valid semantics.
    Nested lists now reject malformed and duplicate rows, use closed field sets,
    and require the entire completion object to equal a deterministic
    reconstruction from all declared unit files.
30. Child containment could still accept the package root itself as an NTFS
    junction because every child resolved consistently under the external target.
    Package generation, bundle preparation, checkpointing, audit validation,
    sealing, amendment commit, and final sealed validation now reject a root-level
    link or reparse point before any read or write.
31. Root-only and selected-boundary checks left unrelated package descendants
    outside the redirect threat model. One shared non-traversing guard now scans
    the complete package tree before every public Python and workbook operation.
32. Base reconciliation accepted a correctly rehashed but altered scaffold or
    neutral queue. Finalisation now reconstructs both exact closed structures
    directly from the two sealed audits before accepting authored dispositions.
33. The former projection reconciliation rebuilt its scaffold, queue, decisions,
    reviews, and seal from cycle evidence to address mutable-scaffold weakness.
34. An operation packet could be changed and rehashed after reconciliation.
    Synthesis became a pure deterministic projection and its former fixed-point
    consumers reconstructed the complete packet. Deterministic reconstruction
    remains required by the current target-validation contract.
35. Fixed-point state and proof could be made internally consistent without a
    genuinely independent replay. That release rebuilt the projected container,
    scan, assurance, ledger, decisions, packet, history, proof, and seals from the
    locked source in an isolated replay workspace. The current product uses
    deterministic target validation without those semantic cycle artifacts.
36. A canonical record and manifest could be replaced by a self-rehashed
    alternative. Canonical sealing now reconstructs the exact record and closed
    manifest inventory from verified predecessors before comparing its seal.
37. A rehashed delivery map could detach workbook semantics from canonical
    authority. Mapping and fidelity validation now independently reconstruct the
    canonical record and exact map, including its closed inventory and seal.
38. Branch coverage measured only a selected correctness kernel, leaving public
    trust-boundary modules unmeasured. The release gate now requires branch data
    and declared per-module thresholds for all 37 Python runtime modules.
39. Online vendor validation could report failed official sources while still
    exiting successfully. The release mode is now strict and fails closed with
    attempted, succeeded, and failed counts; tagged and manual CI releases run it.
40. Consent-gate removal safety evaluated the current route but not a server-route
    addition in the same packet. Target synthesis now evaluates the complete
    projected topology and requires downstream ownership for every affected host.
41. Nested work-unit strategy and workload structures could hide undeclared or
    malformed fields, and derived workload claims could be rehashed. Recursive
    schemas are closed, every error is preserved, and workload is reconstructed
    from locked scan, assurance, and audit evidence.
42. Advanced Consent Mode approval was previously too weakly typed. It now
    requires destination, route scope, route host where applicable, approval
    status, concrete evidence, coherent default/update writers, consent types,
    and Consent Initialization timing visible in locked evidence.
43. Consent applicability could be inferred from broad vendor or destination
    presence rather than actual capability and route topology. Areas 9–12 now use
    route-exact vendor capability, direct/server branch identity, and effective
    destination ownership.
44. One invalid work-unit strategy could stop validation before sibling schema
    defects were reported. Validation now retains the complete deterministic
    error set so malformed evidence cannot hide another obligation failure.
45. Areas 20 and 23 could be marked inapplicable when optional mapping, Zone, or
    Google-settings surfaces were absent even though behavior-bearing web objects
    still carried semantic or portability obligations. Applicability is now
    counted from the complete relevant raw scope and independently assured.
46. Duplicate Configuration or Event Settings variable names were collapsed to
    one export-order owner. Effective-settings facts and assurance now preserve
    every candidate, identify the reference as ambiguous, and conservatively
    retain every candidate route and consent value until semantic audit resolves
    ownership.
47. The public family-work-unit merge entrypoint was the final workflow command
    without its own complete-package redirect preflight. It now guards before
    every read and again before the merged audit write.
48. Rename and pause actions did not participate in the shared write-conflict
    model. They now conflict on `$.name` and `$.paused`, reject contradictory
    packets, and reject blank or no-op operations.
49. Generated intake-question and status channels over-scripted the agent's
    interaction and asked for context that could remain an evidence-bound
    decision. They were removed. Unknown provided context fields still fail the
    closed contract; the agent asks only for the explicitly missing source or the
    smallest non-inferable fact needed for a safe conclusion.
50. Correctly rehashed workbook, editorial, audit, canonical, projection, or
    review manifests could carry `..` or drive-qualified paths and cause reads or
    writes outside the package. One closed canonical-relative-path contract now
    protects every manifest-controlled path in Python and workbook JavaScript
    before I/O, with adversarial outside-file preservation tests.
51. Runtime package verification compared package bytes but did not bind the
    package's declared source commit and complete identity to the expected source
    checkout. Verification now requires a clean full Git commit and exact equality
    of version, tree hash, file count, file map, clean-state flag, and commit across
    source, manifest, and package.
52. Route classification lost a `transport_url` when its value came from a
    Constant or another variable. Route resolution now starts only from explicit
    route fields or Google settings-owner references, follows every candidate
    variable chain conservatively, and independently proves the resulting hosts
    without treating unrelated referenced URLs as transport routes.
53. `gtagConfig` objects participated in destination-linked transport but were
    absent from general effective Google-setting analysis. They are now
    first-class configuration surfaces: direct non-identity parameters retain
    value, provenance, and source coordinates, while same-destination owners get
    independently assured neutral comparisons for equal or conflicting visible
    values.
54. Ecommerce and sensitive-data applicability searched registry-enriched
    configuration review records, allowing official contract metadata to create
    obligations that the container did not contain. Applicability now counts only
    behavior-bearing raw web-container objects and executable custom-template
    code, with independent Area 18 and Area 21 assurance.
55. Common Custom Event filters encoded as `EQUALS|{{_event}}|event_name|` lost
    the configured event name from control topology. The parser now reads the
    paired operands, publishes one complete trigger-control inventory, and the
    independent scan assurance hashes each configured event literal so omission
    or tampering blocks the workflow.
56. Raw ecommerce and sensitive-data applicability was correct in the canonical
    scan, but the obligation ledger could route registry-enriched configuration
    text back into Areas 18 or 21. Configuration obligations are now classified
    only from the exact raw source facts bound by their evidence anchors, and an
    end-to-end regression proves that enriched Google contract metadata cannot
    create object-level obligations in a non-ecommerce, non-sensitive container.
57. Release evidence bookkeeping lagged behind the implementation: the resolution
    count stopped at 51 and the notes called combined coverage branch coverage.
    The count now matches this complete list, and release evidence distinguishes
    aggregate combined coverage from the independently reported branch rate.
58. The approved-requirement evidence reader had only a 13% module coverage floor.
    A dependency-free unit suite now covers deterministic JSON/CSV normalization,
    exact-only object links, XLSX header discovery through the existing runtime
    contract, duplicate identity rejection, and CLI success/failure paths; the
    fail-closed per-module release floor is now 95%.
59. Cookiebot's Zendesk-hosted GTM deployment article returned a repeatable HTTP
    403 from GitHub Actions despite succeeding locally, making the strict release
    gate environment-dependent. The registry now cites Cookiebot's equivalent
    first-party GTM resource on its public product domain, retaining an official
    source while making the same fail-closed check portable across release hosts.
60. The interaction contract still allowed source discovery and generated fixed
    prompts for optional context. Source selection is now always explicit, only
    the validated-start and successful-completion messages are frozen, and every
    other necessary clarification remains contextual.
61. The WEB-only gate still carried dormant server-container Clients,
    Transformations, and server-template code through canonical layers and
    reviewers. Those entities and modules were removed end to end; a server-only
    layer or template section now blocks as unsupported, while web-side
    client-to-server route and consent-forwarding analysis remains intact.
62. The v2.1 release aligned the canonical skill identity, package metadata, UI
    prompt, and evolution record on `gtm-container-audit-optimize`. It also made
    the missing-source request the only frozen start message, added an early
    reuse of the existing workbook-runtime preflight, clarified shared-rule versus
    peer-judgment access, and bounded the static evidence and privacy wording.
63. The v2.1.1 maintenance pass aligned remaining current-facing cleanup wording
    with optimization terminology in inferred context, technical findings,
    human workbook guidance, code guidance, and source navigation. Concrete
    `cleanup_operation` labels and historical or legacy detector terms remain
    where they describe actual removal semantics or source evidence.
64. The v2.2.0 workflow replaced platform-specific independence machinery with
    mandatory fresh-agent scan assurance, two peer-blind complete audits, fresh-
    agent reconciliation, two-agent projection review for materially changed
    obligations, and separate fresh-agent delivery reviews. Lightweight
    provenance retains only agent/context labels and locked input/output hashes.

The stale pre-cutover v1.13 backlog and optional server-audit proposal were also
removed from this document. No server-container audit exists in v2.2.0.

## Release Validation Contract

Release requires all of the following to pass from a clean final commit:

- skill entrypoint validation;
- release structure and semantic-version checks;
- declared runtime identity and clean package/installed-tree equality;
- complete unit and end-to-end workflow tests;
- complete branch-aware coverage gate over every current Python trust-boundary module;
- Ruff and dead-code checks;
- strict fail-closed online official-source registry validation;
- complete workbook-runtime generation and verification;
- exact workbook recovery, comments, fidelity, reader, privacy, formula, and
  rendered-layout checks;
- no stale legacy paths or prohibited local/private residue; and
- Git whitespace and clean-worktree checks.

## Designed Limits And Future Evolution

### Release-readiness goal started (2026-09-03)

The user approved the final 13-section development goal in this conversation.
It supersedes the earlier pending simplification decision, not the product
contract. The North Star remains authoritative in
`references/03-rules/audit-coverage.md`; all seven `AGENTS.md` rules apply.
Local corrections, proportionate implementation simplification and workbook
audit-area filtering are authorized. Product redesign, GTM mutation, pushing,
publishing a release and installing a copy are not authorized.

All eight explicitly named evaluation files were found unambiguously in
`C:/Users/guillaume/Downloads`: the default/cleaned JSON pairs for GTM-NVRJ4J,
GTM-PR4MQ6J, GTM-K2G444H and GTM-MXP9DJG. Their contents have not been opened
in this new goal. Cleaned exports remain comparison evidence, never ground
truth or input to initial independent auditors.

Repeat development evaluations after general improvements until each pair meets
the approved evidence-based comparison condition; normal production execution
remains single-pass. Preserve valid work and resume the failed or earliest
invalidated step instead of restarting the entire run. Revisit earlier pairs
when later changes invalidate their results.

Starting state: the NVRJ4J first-look workbook remains a review copy; final
independent delivery checks and cleaned comparison are unfinished. Other pairs
have not yet been evaluated. No release-readiness claim is made.

First implementation target: inspect and consolidate duplicate canonical
validation in delivery review commands, retaining the existing validation
boundary and adding a focused regression test. Next: the required upper-level
Audit area filter, then continued independent evaluation. No analytical
safeguard has been removed.

#### First correction batch (in progress)

- Removed the duplicate direct canonical checks in delivery-review scaffolding
  and sealing. The editorial validator still validates the canonical record and
  exact delivery projection. A focused fixture checks one canonical invocation,
  rejection of modified canonical content, and no writes on rejected delivery.
- Added Audit area as the second column on all four detail-sheet types. Default
  labels derive from the existing 27-area contract; the existing editorial step
  may choose a controlled upper-level label matching the established issue.
  This is necessary because a code-owned finding can concern consent or duplicate
  loaders. Underlying area IDs remain unchanged and available. Existing fidelity
  review owns category appropriateness; no extra review stage is introduced.
- Removed the four-word quota on operation target, preconditions, verification
  and rollback. Non-blank string requirements, semantic specificity review and
  exact structured-operation validation remain. Removed the obsolete authoring
  schema field and updated its documentation/tests, rather than retaining an alias.
- Verification so far: 11 delivery-class tests, 16 operation-safety tests,
  10 audit-plan tests and the focused duplicate-validation test pass. Bundled
  workbook build/import and delivery-seal fixture passed before the final category
  editorial refinement. A broader earlier run passed 192 tests with two workbook
  tests skipped; it predates the last edits and is not final-candidate proof.
- Current full-suite verification uses the bundled Python/Node/artifact runtime;
  exec session 87502 completed: all 193 tests PASS in 185.298 seconds, no skips.
  Ruff over scripts/tests and Git whitespace checks also PASS.
  The real NVRJ4J workbook is unchanged. Its updated delivery, visual inspection,
  independent reviews and default/cleaned comparison remain pending. No other
  real-container pair has run. No push, release or installation has occurred.

Delivery-only NVRJ4J evaluation preparation: copied the existing validated package
without its generated `delivery` directory to
`C:/Users/guillaume/AppData/Local/Temp/gtm-eval41-delivery-53bd505df7024497a0abbc48f498bbf8/audit-package-audit-area-filter`.
Source package remains `audit-package-delivery-consistency-repair` in that same
parent. Mapper creation is running in exec session 47622; poll this exact handle.
No audits or target synthesis were restarted. The development-only
`transfer_audit_area_editorial.py` in that temp parent is prepared but not yet run:
after mapping succeeds it preserves prior reviewed prose, checks canonical byte
equality and existing fields, and leaves category review pending. Category prose
must be reviewed before editorial sealing; unchanged prior words must not be
replaced with generated stock wording.

Further simplification candidate found by code inspection, not yet changed:
`build_canonical_record` calls `reconciliation_seal_errors` and then
`target_validation_seal_errors`; target reconstruction calls operation synthesis,
which already validates reconciliation. Check this call chain and retain its
failure behaviour before consolidating the repeated check. Do not add caches or
bypass validation. The active delivery mapper run uses the current implementation
and must finish or fail authoritatively before its step is resumed.

Mapper session 47622 completed successfully (1349 rows, all five sheets;
map hash `9280b8e0f1dc9ac3ab529d1518a05c43853720b01a879776c026bca2e7777589`).
The prose-transfer helper then completed: all 1349 reviewed rows preserved,
canonical record byte-identical, category review still pending. No commands or
agents remain active from this correction batch. Next delivery work is to review
the category labels using the established row meanings, seal editorial, rebuild
and visually inspect, then complete the required fresh independent reviews.

#### Second correction batch and first cleaned comparison

Removed the duplicate direct reconciliation validation in canonical construction.
Target reconstruction already validates it through operation synthesis. A focused
test confirms one invocation, rejection of altered reconciliation, and unchanged
canonical output on failure. Exec session 27188 completed: all six canonical
workflow tests PASS. Ruff and whitespace checks pass.

Also removed obsolete server-entity names from the discovery-key recognizer by
deriving its allowed layers from the existing web-only `ID_KEYS` definition.
This eliminates a duplicate layer list rather than adding a new guard. All 17
operation-safety tests pass, including rejection of client/transformation keys
and preservation of supported web object identities.

Fresh editorial agent Feynman `01a068f2-047e-7372-b457-5fe12ee50ead` is reviewing
all 1349 audit-area labels in the audit-area-filter package. Its write scope is
only each row's `prose.audit_area`; all prior wording and semantics are preserved.
It has no cleaned export or comparison results. Main must inspect its result,
then seal/build and run the existing independent delivery reviews. Last wait
returned a timeout, not completion; do not restart the agent.

NVRJ4J default/cleaned comparison has now started after completed initial audits
and the first-look handoff. Raw counts (not superiority claims): default/cleaned/
skill target tags 192/192/191; triggers 133/88/131; variables 133/126/127;
folders 37/37/45; templates 35/23/35. Cleaned retires 51 source trigger IDs and
adds six; its net reduction alone does not prove those changes appropriate.
Skill target removes a duplicate Taboola tag and the obsolete OAuth loader chain
that cleaned retains. Lifecycle removals and owner deferrals still need individual
assessment; no blanket disuse-based deletion policy has been adopted.

Concrete optimisation gap for the next development cycle: source trigger IDs
1276 and 1278 both feed only tag 1349, sharing LINK_CLICK type, URL condition and
explicit false wait/check flags; only the exact Click Text literal differs.
Canonical CD-3B21C109A73E5327 and CD-B21C4172E4C08991 retain separate predicates
as a justified distinction. Cleaned replaces them with trigger 2192 containing a
union regex. Its implicit/malformed listener-option fields differ from source,
so its whole replacement is not accepted as ground truth. The general question
is whether the finite union can preserve every condition, option and consumer
more simply than separate triggers. Updated the existing overlap/domain guidance
to require this assessment, including type/case/line-boundary equivalence and
reasons to retain separate consumers. No case IDs or expected result were added
to production guidance. Official regex operator documentation was read at
https://support.google.com/tagmanager/answer/7679109 on 2026-09-03. Detection and
appropriate proposal remain unproven until a subsequent independent evaluation;
this documentation correction is not counted as a completed analytical fix.

### Prior simplification findings (2026-09-03)

Continuation under the replacement Goal Mode objective: the full 195-test suite
passed in 176.426 seconds. The independent workbook reader rejected audit-area-001
for internal authoring language in Full Audit and current/proposed-state mixing
in Custom Code. The overview, recommendations, decisions and Audit area filtering
were usable; passing technical verification did not establish reader acceptance.
The fidelity review remains independently in progress and has received none of
the reader's findings.

Implemented a general presentation correction: Full Audit's display focus is now
editable prose, while area, fact kind and audit mechanism stay locked. Related
configuration comparisons receive a human-readable default. Updated workbook
rendering and tests, and clarified the existing editorial instructions to separate
source behaviour from proposed repairs. Twelve delivery-class tests passed.
The focused artifact workbook regression passed in 18.088 seconds. These
changes have not yet been applied to a successor NVRJ4J workbook; the failed
reader review and prior workbook remain preserved as evaluation evidence.

Both delivery reviews are now complete and their agents closed. Fidelity reviewed
all 1,349 rows and rejected three: CD-5565033AA316CB9A and CD-B4399480F241AC85
lost their single shared OpenAI pixel research-owner handoff; CD-6DA1385687730884
omitted the bound rationale rejecting a reference-defect claim. Main inspection
confirmed the latter's primary obligation is still AREA-24 naming, with a naming
assessment selected from audit B and a rationale rejecting audit A's reference
claim. Preserve both the primary focus and that rejection context rather than
blindly replacing the finding/category. Custom Code now carries its existing
fact kind and audit mechanism in locked fidelity metadata, just like Full Audit.

Additional simplification: reconciliation seal verification now reuses the
already validated comparison instead of rebuilding it a second time. Fourteen
focused reconciliation/canonical/repair tests passed in 17.919 seconds, including
single-reconstruction checks and rejection of changed scaffold, neutral queue,
record and seal. Public artifacts and semantic decisions are unchanged by this
implementation simplification.

Focused repair staging completed successfully (session 60824), from audit-package-audit-area-filter
to audit-package-delivery-context-repair in the existing eval41 temp root. It
targets the six reader-identified retained code findings listed below, preserving
the predecessor and source audits. After staging, a fresh reconciler must verify
the exact related-operation handoffs and separate current/proposed wording before
dependent target validation and delivery. No agent has been assigned this repair
yet at that checkpoint. Reconciliation was subsequently scaffolded (1,283
comparisons/neutral checks in 43 units) and fresh agent Lovelace
01a06910-603f-7563-8480-3fe90f4e91d1 now owns the focused reconciliation repair.
It may reuse complete unchanged comparisons/evidence after exact equality checks;
it must verify the six changed handoffs from source and existing operations.
The three fidelity findings also remain pending correction at delivery.

The repair CLI had printed its whole inventory receipt (over 31,000 output
tokens in this evaluation). It now returns status, successor, requested IDs and
receipt location/hash; the full persisted evidence receipt remains unchanged.
A focused CLI regression checks that the inventory is not redundantly printed.
The full suite is running as session 39237 (started before this CLI-only edit).
Completed fidelity scratch files were moved out of the repository into
eval41/fidelity-review-working-files; review evidence was not deleted.

Latest regression results: full suite 197 tests passed in 152.109 seconds;
the subsequent focused repair/CLI suite passed all 13 tests in 14.727 seconds.
Ruff and whitespace checks passed. Neither session 39237 nor 19247 remains live.

NVRJ4J naming/folder comparison: cleaned changes only existing tag 2148 and trigger
1031 names and moves only tag 2148 to its new Consent folder. The skill target
already gives 2148 a source-supported OneTrust consent-initialization name and
uses existing folder 2045; raw folder counts are not a quality metric. For trigger
1031, cleaned exposes its exact OneTrustLoaded occurrence, while the skill keeps
Update Consent. Its canonical rationale treats that as a harmless purpose label
and notes that audit A coupled the rename to an unselected alias operation.
This is an operational-clarity opportunity to reassess, not evidence of a firing
defect. Naming guidance now explicitly assesses navigability and clear event/role
identity even when behaviour is unchanged, while preserving clear local names
and rejecting style-only churn. General guidance contains no evaluation IDs;
appropriate detection/target remains to be proved in the next independent audit.

Additional scoped-settings comparison used the existing effective-settings
extractor on default and cleaned, not a new comparison framework. For tags
1962/1966/1969 it found 16/11/11 direct-plus-settings-variable fields respectively,
with no additions/removals and only the already inspected equivalent funnelName
variable alias changing. Tags 1669/1725 retain all six effective fields exactly.
This supports scoped reuse as a real missed optimisation, while limiting the
claim to these tag/ESV surfaces; it does not certify runtime evaluation or the
rest of cleaned's configuration/consent changes.

A focused neutral-scan regression now covers two distinct events sharing a
two-field bundle with an unrelated third event. It verifies exact two-consumer
membership, both source coordinates, neutral/audit-required compatibility status
and independent scan assurance. It passed in 0.322 seconds; no detector/schema
change was needed. This proves the evidence is available for scoped reuse,
not that the agents' next independent judgments already identify it correctly.

Removed the separate operation-family two-word/underscore gate. A concise label
such as Cleanup is valid; the existing shared nonblank-string contract now covers
operation_family along with other operation text, and the plan authoring contract
derives it from that same constant. Structured action, dependency and evidence
checks remain unchanged; delivery still requires a useful human label. Seventeen
operation safety tests passed, including blank/non-string rejection. A subsequent
combined command referenced a nonexistent test_audit_plan module; this was a test
selection error, not a skill execution failure. The actual ten audit-plan tests
in test_v2_workflow.py were run through unittest's name filter. One expectation
still listed the old four-field contract; it was updated to include operation_family.
All ten plan tests then passed in 2.968 seconds, with Ruff/whitespace checks clean.

Release preflight (read-only, 2026-09-03): GitHub repository is
haiqigeng/4-gtm-container-audit-cleanup, with main as its only branch. Latest
published release remains v2.1.1 (2026-09-01); local pyproject.toml identifies
development version 2.2.1. These are not claims of release readiness. Initial
network access was sandbox-blocked; the authorised read succeeded through the
normal elevated permission mechanism. No remote metadata, commit, tag or release
was changed. Select and reconcile the final version only after qualification.

Lovelace completed the focused reconciliation repair and was closed. It changed
the six authorized retained findings' current behavior, assessment, next step and
rationale; 1,277 other conclusions were reused after full input/evidence equality.
All 66 operation proposals and 685 retained source/audit files remained unchanged.
Reconciliation seal: 6fd94aeb3a067639d62b188fb85b2cea8ab91d39f8edf7b4b9947dc546d0a50b.
Main inspected the authored revisions. Operation synthesis passed and retained
the exact predecessor packet and projected-container hashes. Target validation
is now running on audit-package-delivery-context-repair.

This exposed a mapper defect: compact retained-code rows discarded explicit
current_behavior and next_step fields even when the corrected canonical record
supplied them. The mapper now uses those supplied fields and keeps the assessment
in the finding, preserving explicit pending-operation handoffs. Thirteen delivery
class tests passed, including a new retained-code current/pending separation test.

Target validation completed successfully; canonical sealing passed for the
repaired 1,283-decision/66-operation record. Canonical hash:
95d947255b5c70673f412f1b03f9c9fda1e598a8ab8c720db021663f7e362477;
seal c9d8af5c1022beb86fe67a6f2bc5881648cc5c70b4505fd14bfc82a57fd05772.
The focused artifact workbook regression passed in 17.071 seconds. Delivery map
creation is running next. A development-only prose-transfer helper reuses fields
only when their canonical decision and default prose are unchanged, explicitly
excluding the six repaired records and four review-failed rows. It leaves the
editorial pending; it neither seals findings nor supplies approval judgments.

Delivery map creation passed (hash ea307352786d406021b268be2a7eed9265c2745ef577b0a75e903933887aefbc).
The transfer reused 6,683 prose fields and reset ten repaired/review-failed rows.
Main then edited the four presentation-only failures, preserving the single
OpenAI research owner and both the primary naming focus and valid-reference
rationale. The six reconciled descriptions retain their exact pending handoffs.
All 27 distinct display-focus labels were inspected; thirteen internal labels
were replaced with reviewed human wording across 461 rows, and 20 literal wording
occurrences were simplified. These are editable presentation changes only.
Editorial is marked complete and sealing is running; workbook construction,
technical verification and fresh independent delivery reviews remain next.

PR4MQ6J default-only evaluation has now started in parallel with NVRJ4J delivery.
Both explicitly authorised Downloads filenames were resolved; the cleaned file
has not been read or supplied to any initial auditor. Workbook preflight passed.
Evaluation root: C:/Users/guillaume/AppData/Local/Temp/gtm-pr4mq6j-eval-11d4cea3fde24509832c933279861617.
Canonical scan of GTM-PR4MQ6J_default.json is running; fresh assurance and the two
independent audits follow. Keep comparison conclusions out of those contexts.

PR4MQ6J canonical scan passed: 0f2d8ffa828f1e7d3571140b83ee83e4da395f242f4acf647d328c506ad2168b.
Fresh agent Gibbs (01a06927-ec89-71e1-b54b-6126bff4d371) now owns scan assurance
with only the explicitly selected default export, scan and registry. NVRJ4J
editorial sealing passed (8f840828cc637523590de7fab01d067be12ec5694d3468e7dfd85f0b6def3fff);
the repaired workbook is building. No cleaned PR4MQ6J evidence was opened.

Reader-identified Custom Code rows include CD-40EFC123390185FA,
CD-552F0E216E82A31E, CD-62E8D0F4E892636F, CD-E30BE45696B8432D,
CD-EE2649E798B720D7 and CD-FB0EFA2EDA10274F. Bound canonical prose mixes retained
behaviour with pending related operations; exact related operation IDs are often
absent. Pure tense/column placement can be fixed editorially, but a missing
required semantic relationship must return to its owning audit/reconciliation
record. Do not add unsupported handoffs merely to satisfy the reader review.

Latest delivery checkpoint: category-only review completed in fresh agent Feynman
and changed 339 of 1,349 category labels. Main verification confirmed all previously
reviewed prose and canonical judgments unchanged. Editorial sealing passed.
The audit-area-001 workbook built and passed technical verification; all five
rendered previews were inspected, including the expanded Overview evidence-limits
block. The focused artifact workbook regression also passed (18.717 seconds).
Fresh independent delivery reviews are now running: Hooke (reader) and Arendt
(fidelity), using their separate locked bundles only. Current workbook is under
the audit-package-audit-area-filter delivery successor in the eval41 temp root;
the previously delivered first-look review copy remains untouched.

A second comparison gap concerns scoped Event Settings reuse. Source tags
1966/1969 have the same eleven inline fields; source 1669/1725 have the same six
inline fields. None has a direct Event Settings variable reference. Cleaned adds
scoped settings variables 2188/2189, while the current canonical AREA-15 judgments
use a blanket rationale rejecting both global hoisting and overlapping settings
variants. That rationale does not assess these useful bounded groups. The booking
variable's funnelName alias resolves to the same source data-layer definition;
its entire target still needs effective-inheritance/consumer comparison, not blind
acceptance. Updated the existing criteria to distinguish scoped reuse from global
hoisting and require a concrete maintenance/compatibility assessment. Official
Google reusable-event-settings documentation confirms selected GA4 Event tag use:
https://support.google.com/tagmanager/answer/13438771 (read 2026-09-03).
No sealed audit was edited and no analytical fix is claimed proven yet; affected
judgments require fresh independent evaluation with the general criteria.

The current hashes, seals, reconstructed canonical checks, and independent
delivery reviews are production requirements, not development-only tooling.
Repeated evaluations, regression tests, and retained evaluation packages belong
to the development goal. Do not confuse integrity checks with evidence that an
analytical judgment is correct.

Observed duplication: `scaffold_delivery_reviews` and `seal_delivery` explicitly
call `canonical_record_seal_errors`, then call `editorial_seal_errors`, whose
`validate_editorial` -> `_delivery_map_errors` path performs that canonical check
again. Consolidating that repeated work within one invocation is a concrete
optimization candidate; it does not require persistent caches or weaker checks.

Observed delivery friction: the NVRJ4J code-003 workbook passed technical and
human-reader checks, but fidelity rejected two cross-references absent from
their bound canonical rows. Distinguish navigation to an existing established
record from a newly asserted semantic dependency. The latter must still return
to its owning audit/reconciliation stage. Any policy allowing the former needs
an explicit, evidence-backed definition before changing the current contract.

Proposed direction, not implemented: retain complete scan coverage, separate
peer-blind audits, evidence-backed reconciliation, combined-target checks, and
faithful human delivery; consolidate duplicative integrity work and make repair
scope proportional to the actual change. Do not weaken gates simply to pass the
current workbook. The approved goal authorizes implementation simplification;
a broader product redesign remains outside its scope.

- The AI environment must support separate fresh agent contexts. If it does not,
  the audit blocks with a concise capability message rather than requesting
  computer or operating-system configuration.
- Unknown or stale vendor/template contracts block affected recommendations until
  a separately requested skill-evolution action updates the registry and a new
  audit package starts.
- Static evidence cannot certify runtime firing, network receipt, CMP behaviour,
  or downstream server enforcement.
- Server-container audit, runtime recette, GTM mutation, execution approval,
  change logs, and audit deltas may be designed later only as separate authorised
  capabilities. They are not partial or dormant paths in v2.2.0.

### 2026-09-03 — NVRJ4J comparison remains the next qualification priority

The user clarified sequencing: complete the next fresh NVRJ4J development
evaluation before advancing PR4MQ6J semantic audits. The NVRJ4J comparison has
not passed: general criteria for safe trigger unions, scoped Event Settings reuse,
and meaningful naming improvements still need to produce independently justified
results. Counts and improved workbook wording are not comparative utility proof.

The retained NVRJ4J delivery-context-repair workbook built successfully and its
technical-verification.json reports pass with no errors. Delivery review
scaffolding completed (1,349 fidelity rows, five reader sheets); fresh review
verdicts remain pending. The original first-look workbook is unchanged.

PR4MQ6J scan assurance completed independently with all 19 checks passing.
Package creation stopped at runtime identity preflight because the development
checkout contains uncommitted fixes and an outdated build manifest. No semantic
audit started. Preserve that assurance evidence; do not bypass identity checks.
After testing and committing the general fixes, build an identified candidate
and use it for a fresh NVRJ4J default-only evaluation. Keep prior findings and
the cleaned comparator out of both independent audit contexts. Development
repetition does not alter the skill's single-pass production workflow.

Candidate checkpoint validation: all 200 unit/integration tests passed in 153.198
seconds with the bundled workbook runtime enabled; Ruff and git diff --check
passed. These checks cover implementation regressions, not comparative audit
superiority. Fresh NVRJ4J scan passed with source SHA-256
867657364262f86a52fdea7a064add569e6669d3b834155e73bf8b08c2ab8fb6;
the independent assurance step is in progress in its own context.
