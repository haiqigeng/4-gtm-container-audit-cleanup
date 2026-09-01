# GTM Container Audit & Cleanup — v2 Evolution Record

## Status And Authority

This document records the product decisions that produced the v2 static audit
workflow. It is an evolution record, not a second runtime contract.

The authoritative implementation sources are:

- `SKILL.md` for activation, workflow, and hard boundaries;
- `references/03-rules/audit-coverage.md` for the North Star and all audit areas;
- `references/03-rules/workflow-and-assurance.md` for independence, reconciliation,
  and fixed-point closure;
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

## Current Phase Boundary

The v2 workflow accepts one complete GTM **web-container** export or equivalent
read-only evidence and ends at one validated analyst workbook.

It does not:

- audit a server container or accept a server-container export;
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
folders, templates, Zones, settings, destinations, clients, and transformations.
Detect cycles, missing references, ambiguous targets, and all consumers that must
be remapped before retirement.

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
Never request or inspect a server-container export in v2.

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

### 20. Transformations And Source-To-Destination Semantics

Trace values through variables, transformations, settings, overrides, payloads,
and destinations, preserving type, cardinality, null, empty, zero, false, array,
and object meaning. Prefer fixing the source over keeping compensating transforms.

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

### 27. Exact Operations And Fixed-Point Cleanup

Compile exact creates, additions, changes, named-field removals, remaps, renames,
pauses, deletions, dependencies, verification, and rollback. Project the complete
target and repeat global closure until stable or deterministically blocked.

## Decided Workflow

### Stage 1 — Lock Evidence

Lock the complete web source, context, runtime identity, audit contract, vendor
registry, approved requirements, and exact `do_not_touch` keys. Package creation
must pass source identity and independent scan assurance before semantic review.

### Stage 2 — Canonical Scan And Assurance

Build one neutral fact layer and typed obligation ledger. Independently reread raw
JSON to verify object/reference/variable/trigger/settings/consent/route/code/
vendor/candidate/ownership/branch identities and exact area coverage. Every
inapplicable mechanism needs a source-counted zero.

The scan may create candidates but may not carry a verdict, recommendation,
selected policy, operation requirement, or target hint.

Area 1 closes through this evidence/assurance gate, areas 2–26 through both
semantic audits, and area 27 through operation synthesis and fixed-point proof.

### Stages 3 And 4 — Two Complete Independent Audits

Run two complete host-scoped audits concurrently:

- Audit A traverses object and implementation chains first;
- Audit B traverses families and target architecture first.

Both cover every applicable semantic obligation. Separate allowlisted bundles,
context IDs, and host-issued isolation receipts are mandatory. Audit B is
generated-candidate-blind until its source-only checkpoint. Neither audit may see
the other's work before both are sealed.

### Stage 5 — Neutral Reconciliation

Compare atomic decisions by exact obligation, subjects, family, relationship, and
target. Expose agreements, complements, one-sided findings, conflicts, and
different evidence boundaries. Never vote, average, or silently select.

Use a fresh identity-blind neutral verifier for every disagreement, one-sided
finding, and material-risk class. The verifier may confirm, narrow, reject, or
keep blocked; it cannot invent a third actionable target.
Each neutral context is host-scoped to one hash-bound bundle and has a unique
receipt. Source-audit, peer-neutral, projection-review, and prior-cycle context
identities are forbidden.

### Stage 6 — Target Synthesis And Fixed Point

Compile only reconciled and required-neutral-verified decisions into exact
operations. Every cycle starts from the locked original, applies the full packet,
reruns global scan and assurance, and sends every new or changed semantic
obligation to two fresh isolated reviews plus required neutral checks.

Allow at most three cycles. Block as `non_convergent_target_state` on cycle-three
actionability, recurring actionable hashes, oscillation, conflict, or the absence
of an exact safe operation. Replay the stable packet from the original and require
the complete hash tuple to match before canonical sealing.
Candidate next cycles are staged and validated before the packet, projection
decisions, and cycle directory commit. Failure restores the prior committed
artifacts and leaves no partial next cycle.

### Stage 7 — Human Workbook

Map the sealed canonical record to one human workbook. A missing or incorrect
mandatory delivery field starts a complete same-source successor package bound to
the predecessor canonical seal and an approved repair brief. Both fresh audits
and neutral reconciliation own the correction before a new record is sealed.
Delivery never patches or overwrites a sealed semantic record.

An editorial context may improve declared prose fields only. Deterministic
workbook build, exact recovery, fidelity review, workbook-only reader review,
rendered inspection, privacy, and formula-injection checks must all pass.

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
raw evidence, projected closure, or the static evidence boundary. Audit-result
quality and trustworthiness remain the primary objective; time to result is
secondary.

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
| Independent review | Replaced by two complete isolated audits plus targeted neutral verification |
| Target operations | Retained within the static phase and strengthened by projection/replay |
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
- Scanner, assurance, obligation, audit isolation, reconciliation, operation,
  fixed-point, canonical record, and delivery concerns remain separate modules.
- The existing optional parser and bundled spreadsheet artifact runtime are used;
  no duplicate authoring library was introduced.
- The fixed-point and semantic-successor repair contracts are long-term invariants, not
  temporary bridges.
- The v2 cutover occurred only after a complete scan-to-workbook path passed.

## Final Release Review And Resolutions

The repeated pre-release review found and resolved eighteen issues:

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
9. Neutral verification required fresh IDs but lacked a host-bound bundle receipt
   and could reuse source or prior-cycle reasoning identities. Every base and
   projection neutral now has a deterministic allowlist hash, enforced receipt,
   and global context/receipt non-reuse checks.
10. A canonical semantic defect could identify its owning record but the sealed
    workflow had no executable repair path. The builder now creates immutable
    same-source successor packages bound to the predecessor canonical seal and an
    approved field-level repair brief; every repair enters both fresh audits as a
    post-checkpoint requirement on its exact owning obligation.
11. Next-cycle preparation wrote projection decisions and the operation packet
    before cycle assurance completed. Candidate cycles are now staged; failure
    restores the preceding records, removes staging, and deterministically blocks
    without a partial cycle.
12. A tagged release and runtime manifest could accept dirty build provenance.
    Tagged release checks and declared/installed runtime identity now fail unless
    the manifest records a clean source commit.
13. Projection reviews checked context freshness against source audits and prior
    projection reviews only, so a base-neutral context or receipt could be reused.
    One shared ownership-aware registry now covers checkpoints, audit history,
    every neutral, every projection review, editorial versions, and delivery
    reviews; both context and receipt reuse block before sealing.
14. Fidelity and workbook-only reader checks compared their identities only with
    each other and the editorial context, so a source-audit identity could pass
    the delivery gate. Delivery now checks both reviewers against the same
    workflow-wide registry and the final seal independently rejects any cross-
    owner collision.
15. The documented pre-canonical audit amendment path could not satisfy both its
    checkpoint identity lock and fresh-context rule. Amendments now retain the
    immutable source checkpoint, use a globally fresh context and receipt, bind
    both artifact and receipt to the current prior audit seal, and archive the
    prior audit and seal only after every validation passes.
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
    audit hashes, receipt-parent bindings, and unchanged checkpoint/release
    provenance through the full chain.

The stale pre-cutover v1.13 backlog and optional server-audit proposal were also
removed from this document. No server-container audit exists in v2.

## Release Validation Contract

Release requires all of the following to pass from a clean final commit:

- skill entrypoint validation;
- release structure and semantic-version checks;
- declared runtime identity and clean package/installed-tree equality;
- complete unit and end-to-end workflow tests;
- correctness-kernel branch coverage gate;
- Ruff and dead-code checks;
- online official-source registry validation;
- complete workbook-runtime generation and verification;
- exact workbook recovery, comments, fidelity, reader, privacy, formula, and
  rendered-layout checks;
- no stale legacy paths or prohibited local/private residue; and
- Git whitespace and clean-worktree checks.

## Designed Limits And Future Evolution

- Host isolation must be enforced by the orchestration environment; artifact
  validation can prove receipt and manifest consistency but cannot manufacture
  access control.
- Unknown or stale vendor/template contracts block affected recommendations until
  a separately requested skill-evolution action updates the registry and a new
  audit package starts.
- Static evidence cannot certify runtime firing, network receipt, CMP behaviour,
  or downstream server enforcement.
- Server-container audit, runtime recette, GTM mutation, execution approval,
  change logs, and audit deltas may be designed later only as separate authorised
  capabilities. They are not partial or dormant paths in v2.
