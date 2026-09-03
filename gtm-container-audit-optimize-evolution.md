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
