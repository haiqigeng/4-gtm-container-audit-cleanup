# GTM Container Audit & Cleanup — Evolution Backlog

## Purpose

This file records the decided North Star, final scan-and-audit coverage contract,
decided target audit and human-delivery workflow, and confirmed optimisation
opportunities for
`gtm-container-audit-cleanup` after reviewing release `v1.13.0` against this
project's `AGENTS.md` and the Codex `skill-creator` workflow.

It is a working evolution backlog, not an instruction to mutate a GTM container.
Changes to the skill remain separate from any live GTM execution or publication.

## Passing Baseline

The current release is a sound baseline, not a broken package:

- the installed source matched the latest upstream `main` and `v1.13.0` tag;
- Codex skill validation, package identity, self-test, vendor-registry, Ruff,
  Vulture, release, and whitespace checks passed;
- all 277 unit tests passed;
- measured coverage was 86%, above the existing 72% gate;
- the package currently contains a 238-line `SKILL.md`, 41 Python scripts,
  21 Markdown references, and eight `test*.py` modules.

Every evolution step must begin and end from a passing baseline. A refactor is
not complete merely because files are smaller; every capability retained for the
current phase, its safety invariants, and its release checks must remain correct.
Capabilities deliberately deferred by the phase boundary below receive an
explicit disposition instead of remaining as accidental partial features.

## Non-Negotiable Quality And Safety Invariants

Evolution must preserve existing safety guarantees and establish the target
workflow controls that have concrete GTM quality or trust reasons:

- complete source identity and evidence locking;
- one complete deterministic scan with an independent raw-source assurance path;
- two complete clean-room semantic audits, authored and sealed without access to
  each other before reconciliation;
- neutral fresh-context verification of disagreements, one-sided findings, and
  material-risk conclusions;
- deterministic neutral facts separated from semantic verdicts;
- complete review depth with no reduced audit mode;
- contradiction-aware reconciliation and future-state simulation;
- exact, decision-ready operation IDs, dependencies, static verification, and
  rollback in the delivered plan;
- strict `do_not_touch`, consent, routing, activation, and decommission risk
  disclosure in every affected recommendation;
- no GTM mutation, import application, version creation, publication, or claim
  of executed change in this phase;
- one purpose-built analyst workbook generated from the sealed canonical record,
  with exact delivery coverage and no semantic drift; and
- separation between that human deliverable and the canonical technical record.

These controls are justified complexity. Simplification should remove accidental
complexity around them, not remove the controls themselves.

## Current Product Direction

The immediate product step is to make the skill a complete GTM optimisation
analyst, not merely a stronger defect finder. This phase operationalises the
decided North Star and master coverage below through the decided audit and
human-delivery workflow, before internal refactoring.

The analytical contract must answer two separate questions for every relevant
object, implementation chain, relationship candidate, and measurement family:

| Question | Required conclusion |
| --- | --- |
| What is wrong? | A source-visible defect, contradiction, unsafe configuration, or precise evidence limit. |
| What can be better? | A materially simpler, more reusable, more coherent target that preserves required behaviour. |
| Why should it stay as it is? | The positive source-visible distinction that makes the current design appropriate. |
| What cannot be decided? | One exact owner decision or external evidence boundary, without inventing runtime facts. |

Correctness and optimisation are not synonyms. A working tag can still be
needlessly repetitive. Conversely, a different-looking implementation is not an
optimisation candidate unless a better target is source-supported.

### Optimisation threshold

Record an optimisation opportunity only when all of the following are true:

1. the current repetition, fragmentation, unnecessary customisation, or control
   complexity is visible in the locked container;
2. the proposed target uses a current GTM mechanism supported for the detected
   object and product;
3. required source, output, type, shape, timing, consent, route, destination,
   consumer, and ownership distinctions are preserved;
4. the target produces a concrete benefit such as fewer independently maintained
   copies, one clearer owner, less configuration drift, a smaller error surface,
   or replacement of unnecessary custom code;
5. the exact create, update, remap, override, and retirement operations can be
   expressed from source-visible or explicitly confirmed values; and
6. the proposal does not claim runtime improvement, vendor receipt, or business
   equivalence that the container cannot prove.

Do not emit “best practice” advice, wrap every literal in a variable, consolidate
by count, or create shared objects whose only benefit is stylistic indirection.

## Decided North Star

> Make an existing GTM container as clean, correct, simple, and maintainable as
> if a senior web analyst had configured it today from an empty container for the
> same proven needs. Using only container-visible evidence, identify what is
> wrong, what can be improved, and what should stay, then turn every justified
> improvement into an exact, safe target state and deliver it in one trustworthy,
> human-readable analyst workbook.

This is the authoritative product outcome for the next evolution phase. It adds
greenfield-quality optimisation to the existing cleanup mission without changing
the container-only evidence boundary or weakening the proof required for any
recommended change.

### Current Phase Completion Boundary

This phase is complete when the sealed canonical audit and operation record has
produced one validated analyst workbook. The workbook is decision-ready: it gives
the analyst stable operation IDs, exact targets, dependencies, risk disclosures,
static verification, and rollback. It is not an execution authorisation or proof
that GTM was changed.

Analyst approval and later implementation through an authorised GTM MCP or other
GTM provider are separate follow-up work. Approval packets, direct mutation,
import JSON, pre-execution drift checks, post-change readback certification,
change logs, and audit-to-audit deltas are deliberately deferred to future
versions. Do not leave partial implementations or compatibility hooks for those
utilities in the target runtime. Until a later version defines their complete
contracts, this skill must not mutate GTM, create or apply an import, create a
version, publish, or describe a recommendation as executed.

## Final Scan And Audit Coverage Contract

This is the master audit coverage contract. It consolidates the current skill's
in-scope behavioural coverage into the new evidence and obligation model and adds
the deeper cleaning and valid-but-non-optimal architecture review required by the
decided North Star. Preserve useful behaviour, not obsolete run names, schemas,
workbook shapes, or compatibility paths.

Apply it at four levels:

1. **Object:** one tag, trigger, variable, template, Zone, client,
   transformation, or configuration resource;
2. **Chain:** source to variable to transformation/settings to trigger to tag to
   route and destination;
3. **Family:** related loaders, events, destinations, consent controls, routes,
   and business purposes; and
4. **Container:** ownership, duplication, coupling, portability, naming,
   maintainability, and the complete target architecture.

For every area below, **Scan** means deterministic extraction, graphing, or
candidate generation from locked evidence. **Audit** means source-bound senior
analyst judgment. A candidate is never a verdict. The detailed semantic backlog
remains the implementation contract for how these coverage areas become facts,
decisions, operations, tests, and workbook rows.

### Consent And Routing Decision Model

Classify every consent-relevant route into exactly one class before judging its
triggers or consent controls:

| Route class | Positive firing trigger | Consent-control owner | Required audit position |
| --- | --- | --- | --- |
| Consent infrastructure | Consent Initialization or the CMP's documented default/update lifecycle event | The consent writer itself | It establishes or updates consent state and is not vendor-gated. Keep it separate from normal vendor tags. |
| Confirmed Advanced Consent Mode | The normal lifecycle or business event, with no consent-granted condition | Coherent Consent Mode defaults and updates plus the product's intrinsic behaviour | Do not add a manual consent blocker or Additional Consent Check. Native capability alone does not prove Advanced Consent Mode. |
| Pure client-to-server transporter | The normal lifecycle or business event, with no consent-granted condition | One canonical consent-state value forwarded to the server; every downstream vendor decision is owned by the server container | With respect to consent, keep only firing triggers: no client consent blocker, positive consent condition, or Additional Consent Check. |
| Every other direct browser/vendor route, including a Google route that is not confirmed Advanced Consent Mode | A consent-free lifecycle/CMP-timing event for page-load behaviour, or the real business custom event for later actions | One reusable vendor, purpose, or category denial blocker | The blocker is mandatory, absent/unknown/denied state fails closed, and consent must not be duplicated in the positive trigger or Additional Consent Checks. |

Apply these rules without exception inside the selected architecture:

- A CMP event may provide timing or readiness for a page-load tag, but the
  positive trigger must not contain a granted-state condition. Consent eligibility
  belongs to the blocker for direct non-Advanced routes.
- For later clicks, forms, ecommerce, and other business actions, retain the real
  business event as the firing trigger and apply the same reusable blocker.
- A template-declared Built-In Consent Check is intrinsic product metadata, not a
  configurable substitute for this decision model. Record it, do not try to
  disable it, and do not add an Additional Consent Check when the selected owner
  is the reusable blocker, confirmed Advanced Consent Mode, or the server.
- Confirmed Advanced Consent Mode requires explicit approved context and a
  coherent container-visible default/update implementation. A Google tag's
  capability or built-in consent metadata alone is insufficient.
- A pure transporter has no direct browser vendor script or request on that
  route. It passes one complete canonical consent-state variable through the
  Google tag or shared setting inherited by every transported event. Missing,
  multiple, inconsistent, partially inherited, or inline copies are findings.
- A mixed direct-and-server implementation does not receive the transporter
  exception for its direct branch. Split and judge the branches separately; if
  they cannot be separated, apply the direct-route control requirement.
- This version never requests, accepts, or audits a server-container export. The
  strongest permitted conclusion is: **Client transport and consent-forwarding
  contract aligned; downstream server enforcement not audited.**

### 1. Source Identity And Evidence Completeness

- **Scan:** account, container, workspace/version IDs, container type, export
  timestamp, and whether evidence represents a published version, latest version,
  or workspace; enumerate tags, triggers, variables, built-ins, folders, custom
  templates, Zones, `gtag_config` resources, destinations, and environments;
  detect malformed JSON, invalid collection shapes, duplicate IDs, and absent
  entity layers; reject a `SERVER` container instead of switching audit modes.
- **Audit:** produce an evidence-completeness manifest; block ambiguous identity,
  partial evidence, or any unmodelled layer that could change a verdict; never
  infer an unseen server container or omitted resource.

### 2. Object Inventory And Identity

- **Scan:** record every object's key, ID, exact and normalised name, type,
  status, folder, notes, template/version, and relevant metadata; detect case,
  whitespace, Unicode/confusable, placeholder, development, test, and migration
  naming signals.
- **Audit:** assign the evidenced role, vendor, destination, purpose, route, and
  owner; distinguish unknown purpose from an obsolete object and identify
  abandoned, temporary, or migration machinery only from positive evidence.

### 3. Dependency And Reference Graph

- **Scan:** recursively resolve variable references, firing and blocking
  triggers, trigger groups, setup/teardown chains, folders, templates, Zones,
  configuration/settings resources, destinations, and server relationships;
  enumerate consumers, active roots, missing or ambiguous references, cycles,
  self-references, and orphan cycles.
- **Audit:** decide whether each dependency is required, accidental, broken, or
  sequence-only; require exact consumer remaps before retirement and permit no
  unresolved cycles in the target graph.

### 4. Lifecycle, Reachability, And Usage

- **Scan:** classify active and paused objects, unused objects, objects consumed
  only by paused objects, tags with no direct firing route, schedules,
  environment/live-only controls, rollback markers, and malicious or suspicious
  remnants.
- **Audit:** never delete merely because an object is old, paused, or unused;
  establish current need, rollback value, lifecycle owner, and safe disposition,
  then recompute reachability after every consolidation or remap.

### 5. Exact Duplicates And Functional Overlap

- **Scan:** detect duplicate names, structural and behaviour signatures, custom
  code, data-layer paths, payloads sent through different routes, vendor/
  destination/event families, loaders, page views, consent writers, near-
  duplicate triggers, subset triggers, and environment or naming drift.
- **Audit:** classify each relationship as exact duplicate, functional overlap,
  conflict, intentional variant, migration pair, or insufficient evidence;
  preserve every material difference in event, timing, payload, consent, route,
  destination, market, product, or owner.

### 6. Tag And Template Configuration

- **Scan:** capture tag type, template identity and version, publisher,
  permissions, destination IDs, fields, parameters, missing required values,
  deprecated settings, and multi-vendor behaviour.
- **Audit:** resolve current official product and installed-template contracts;
  prefer native GTM capability, then an official or well-maintained reviewed
  template, before custom code; classify each configuration as defective,
  correct-but-non-optimal, justified, obsolete, or evidence-limited.

### 7. Trigger Event And Condition Topology

- **Scan:** model firing routes as OR, conditions inside a trigger as AND, and
  blockers as an intersection with each eligible event; capture trigger types,
  event names, filters, regexes, contradictions, overlap/subset/disjoint
  relationships, trigger groups, lifecycle events, SPA/history events, and
  sequence invocation.
- **Audit:** prove the intended occurrence and data-availability contract; detect
  weak click/DOM selectors, duplicate or subsumed routes, impossible conditions,
  and groups that do not represent a real AND lifecycle; preserve intentionally
  scoped differences.

### 8. Firing Options, Priority, Scheduling, And Sequencing

- **Scan:** enumerate explicit priorities including `0`, potentially co-eligible
  tags, once-per-event/page and unlimited firing options, setup/teardown links and
  failure settings, direct triggers on sequence-only tags, cycles, and schedules.
- **Audit:** remove explicit `0`, priority with no same-event competitor, priority
  already owned by sequencing, and priority used as an asynchronous completion
  mechanism; retain nonzero priority only for an evidenced same-event start-order
  need; require loaders to initialise once per intended lifecycle and business
  tags to fire once per intended event.

### 9. CMP And Consent Infrastructure

- **Scan:** identify CMP and version, documented events and variables, token
  format, default and update writers, Consent Initialization usage, Google consent
  types, duplicate writers, unknown-state behaviour, consent conditions in
  positive triggers, blockers, Built-In Consent Checks, and Additional Consent
  Checks.
- **Audit:** resolve exact current CMP/vendor contracts; ensure defaults exist
  before dependent tags, updates map correctly, unknown state fails closed where
  client blocking applies, Built-In and Additional checks are not conflated, and
  timing/readiness remains separate from vendor eligibility.

### 10. Direct Client-Side Consent Architecture

- **Scan:** for every direct browser/vendor tag, capture positive event and
  filters, any consent condition in that positive route, all blockers and their
  consumers, CMP state source and token matching, Additional Consent Checks,
  repeat events, firing options, and later-grant behaviour.
- **Audit:** except for confirmed Advanced Consent Mode and pure transporters,
  require a consent-free positive trigger plus one reusable vendor/purpose/
  category denial blocker; prove same-event intersection, exact token boundaries,
  fail-closed unknown state, correct policy scope, idempotence, and replay limits;
  remove duplicate consent conditions and do not claim that a blocker unloads a
  vendor or implements withdrawal at runtime.

### 11. Advanced Consent Mode

- **Scan:** inventory relevant Google tags and destinations, consent defaults and
  updates, consent types, event timing, Built-In metadata, manual blockers,
  Additional Consent Checks, positive consent conditions, and direct/server
  route.
- **Audit:** classify a route as Advanced only with explicit approved context and
  coherent source-visible defaults/updates; then use the normal event, remove
  manual blockers and Additional checks, preserve intrinsic product behaviour,
  and expose every missing or contradictory consent type. Otherwise apply the
  direct non-Advanced route policy.

### 12. Client-To-Server Transporter Architecture

- **Scan:** capture server URL and transport fields, their configuration owner,
  every inheriting tag, direct browser vendor bypasses, the canonical consent
  variable and its terminal source/type/default/update path, the exact shared
  forwarding field, inline duplicates, blockers, Additional Consent Checks,
  positive consent conditions, destinations, event IDs, and browser/server
  overlap.
- **Audit:** grant the transporter exception only to a pure route; require normal
  firing triggers, no client consent gate, one complete canonical consent value
  configured once and inherited by every transported event, and no direct vendor
  bypass; flag missing, multiple, inconsistent, partial, non-inherited, inline,
  blocked, or mixed-route implementations and state the downstream server
  evidence boundary exactly.

### 13. Server-Container Consent, When Separately Supplied

- **Scan:** trace the claiming client, incoming consent event-data field,
  transformations, field mutations, mapping/default logic, downstream vendor
  tags and triggers, browser/server event IDs, and possible bypass routes.
- **Audit:** prove that each downstream vendor decision is server-owned, correctly
  mapped, and fail-closed; detect dropped, overwritten, or swapped consent values,
  ungated bypasses, and static duplicate routes; do not certify runtime requests,
  vendor receipt, or enforcement.

### 14. Variable Graph And Source Contracts

- **Scan:** recursively resolve terminal source, variable type, data-layer path,
  default, format, null/undefined behaviour, built-ins, constants, lookup and
  regex tables including every row, Custom JavaScript, duplicate terminal
  sources, and all consumers.
- **Audit:** use the simplest compatible rung: built-in or direct data-layer
  variable, stable constant, shared settings, deterministic lookup/regex table,
  native template, narrow transformation, then Custom JavaScript; reject needless
  abstraction, unsafe defaults, type/shape drift, and one-consumer indirection
  without a maintenance benefit.

### 15. Effective Google Configuration And Field Ownership

- **Scan:** resolve each effective field across Google tag, `gtag_config`,
  Configuration Settings variable, Event Settings variable, event tag, inherited
  setting, and inline override; record field provenance, value, type, lifetime,
  consumers, destination, consent relevance, and browser/server route.
- **Audit:** assign configuration-wide settings to one configuration owner,
  genuinely shared event parameters to an Event Settings owner, and event-specific
  values locally; remove redundant identical inline copies, retain justified
  overrides, expose conflicts, and avoid broad shared objects that create
  unrelated coupling.

### 16. Destination, Loader, And Page-View Ownership

- **Scan:** inventory destination IDs, loaders/config tags, connected-destination
  evidence, `send_page_view`, manual and history page views, linker/cross-domain
  fields, browser/server routes, and brand, market, product, or environment scope.
- **Audit:** establish one deliberate loader/config and page-view owner per
  destination and route; preserve intentional multi-destination and scoped
  variants, remove duplicate initialisation or page views, and label
  property-side connected-destination behaviour as an external boundary.

### 17. GA4 Event And Parameter Correctness

- **Scan:** classify recommended, automatically collected, enhanced-measurement,
  and custom events; inspect event-name spelling/case/limits/reserved names,
  parameters, inheritance, parameter counts and types, user properties, debug and
  traffic fields, destination, and page-view ownership.
- **Audit:** prefer current recommended semantics when they fit; require their
  documented parameters, correct scope/timing/cardinality, and coherent types;
  distinguish a definite container duplicate from a potential GA4-property or
  enhanced-measurement duplicate.

### 18. Ecommerce

- **Scan:** inspect ecommerce events, `items`, item fields, transaction ID,
  value, currency, tax, shipping, coupon, scope, duplicate purchase/refund routes,
  fixed item slots, legacy syntax, and browser/server deduplication fields.
- **Audit:** require one intentional route per destination, complete item arrays,
  correct quantity and monetary semantics, purchase/refund linkage, and no
  invented defaults; reject fixed item slots and parallel schemas unless a proven
  contract requires them; keep runtime uniqueness and finance reconciliation out
  of scope.

### 19. Ads, Floodlight, And Other Vendor Tags

- **Scan:** capture base/config and event/action tags, IDs, labels, event names,
  values, products, matching fields, deduplication keys, browser/server routes,
  templates, custom scripts, and deprecated fields.
- **Audit:** compare each integration with current official vendor/template
  documentation; detect duplicate loaders or actions, wrong IDs/labels, obsolete
  semantics, incoherent route/deduplication, and non-optimal custom implementations;
  research unknown integrations before issuing a definitive verdict.

### 20. Transformations And Source-To-Destination Semantics

- **Scan:** trace every material value from source through variables,
  transformations, lookup/settings layers, inline overrides, payload field, and
  destination; record type, cardinality, missing/null/empty/zero/false behaviour,
  array/object handling, repeated keys, and fallback branches.
- **Audit:** preserve business meaning and do not flatten arrays, select a first
  value, coerce types, or invent defaults without an evidenced contract; separate
  extraction, normalisation, business mapping, and destination formatting, and
  fix the real source instead of retaining compensating transforms where possible.

### 21. First-Party Data, Identity, And Privacy-Sensitive Fields

- **Scan:** inventory GA `user_id`, user properties, `user_data`, Ads enhanced
  conversions, vendor matching, hashes, PII-like values in fields or URLs, DOM
  selectors, hashing method, secrets, and logging/debug exposure.
- **Audit:** assign one clear owner per identity product and destination, prevent
  raw PII and double hashing, keep distinct vendor products separate, require the
  selected consent architecture, and report product-policy or legal questions as
  explicit external decisions rather than legal conclusions.

### 22. Custom Templates And Custom Code

- **Scan:** inspect template metadata, permissions, allowed domains, code and
  parser behaviour, Custom HTML/CJS, script and request injection, globals,
  `dataLayer` resets, cookies/storage, DOM access, listeners, timers, `eval`, HTTP
  origins, secrets, clones, callbacks, and asynchronous completion paths.
- **Audit:** explain all material behaviour and side effects; prefer native or
  reviewed template replacements only after exact value/type/timing/consent/
  route equivalence; require narrow purpose, guards, one-time behaviour, safe
  origins, and maintainability; treat opaque code as an evidence limit, not proof
  of correctness.

### 23. Zones, Environments, And Portability

- **Scan:** enumerate Zone boundaries and child-container references,
  restrictions, duplicated parent/child responsibilities, unbounded permissions,
  environments, embedded IDs and hosts, and production-default behaviour.
- **Audit:** require explicit safe routing and least necessary Zone scope; preserve
  environment and child-container separations unless equivalence is proved;
  record unseen child containers as boundaries and remove hard-coded portability
  constraints only when their target replacement is known.

### 24. Naming, Folders, Notes, And Documentation

- **Scan:** detect inconsistent, ambiguous, duplicate, malformed, corrupted, and
  placeholder names; map folders, notes, and missing ownership/purpose metadata.
- **Audit:** name objects so type, owner/vendor, purpose, event, destination, and
  meaningful scope are understandable; use folders only when they aid operations;
  apply naming after canonicalisation and never create cosmetic-only operations.

### 25. Static Efficiency And Complexity

- **Scan:** measure container size and object counts, custom-code volume,
  duplicate script or listener bodies, large tables, repeated parameters, high fan-out,
  deep dependency chains, and one-consumer abstractions.
- **Audit:** reduce independently maintained definitions and failure surfaces
  without creating opaque coupling or a risky shared owner; avoid minimum-count
  targets and do not claim runtime performance from static container evidence;
  identify site-side JavaScript that GTM should not own as a handoff, not a silent
  container rewrite.

### 26. Business Architecture And Greenfield Target State

- **Scan:** group every object into source-derived families by business event,
  vendor, destination, loader/configuration, consent owner, server route, source,
  market, brand, product, and implementation chain; include singletons and open
  relationship discovery.
- **Audit:** decide the proven measurement need, canonical objects, intentional
  variants, conflicts, omissions visible from configured intent, and simplest
  architecture; state for every family what is wrong, what is materially
  non-optimal, what should stay and why, and what a senior analyst would build
  from an empty container for the same proven needs.

### 27. Exact Operations And Fixed-Point Cleanup

- **Scan:** compile creates, updates, remaps, override removals, renames, pauses,
  deletions, and dependency order; compute effective before/after values and the
  future reference graph; rescan reachability, conflicts, names, cycles, consent,
  routes, and newly unused objects until no new operation is implied.
- **Audit:** choose the simplest exact operation chain, preserve every required
  consumer and behaviour, avoid partial migrations and debris, expose decisions
  that block an exact target, and require simulation plus static post-change
  verification before an operation becomes decision-ready in the workbook.

### Mandatory Decision And Evidence Contract

Every relevant object, chain, family, and relationship candidate receives exactly
one primary decision class:

1. **Defect:** configured logic is wrong, contradictory, unsafe, broken, obsolete,
   or inconsistent with its evidenced contract.
2. **Correct but materially non-optimal:** behaviour can be preserved with a
   simpler, clearer, more reusable, or lower-drift target.
3. **Justified as-is:** a positive source-visible distinction proves why the
   current design should stay.
4. **Owner decision:** container evidence exposes a real choice whose target
   depends on business, policy, lifecycle, or ownership confirmation.
5. **Container evidence limit:** the conclusion requires runtime, website,
   property, vendor, server, or other evidence outside the supplied scope.

Every proposed change must name the evidence, affected objects and consumers,
exact target state, ordered operations, expected maintenance or correctness
benefit, behaviour and consent risks, static verification, and rollback basis.

### Hard Evidence Boundaries

Do not claim actual firing, runtime data-layer values, browser/network requests,
cookie behaviour, CMP UI behaviour, vendor receipt, GA4 property settings,
runtime deduplication, legal compliance, runtime performance, downstream server
enforcement when its export is absent, or missing measurement merely from the
absence of a tag. Preserve source locking, pre-reconciliation review isolation,
contradiction-aware reconciliation, simulation, sealed-record integrity, and
human-delivery fidelity as separate safety layers. The decided workflow below
replaces the fixed three-run structure only after its proof gate passes. Do not
imply mutation, readback, or runtime verification beyond the current phase.

### Source Policy

Resolve version-sensitive criteria in this order:

1. official Google/GTM documentation and APIs;
2. the installed template's source, schema, permissions, and metadata;
3. official CMP or vendor documentation;
4. reputable third-party material for discovery only; and
5. clearly labelled analyst inference where no stronger source exists.

Record the source URL, access date, applicable product/template version, and the
rule it supports. A source can establish a product contract; it cannot replace
the container evidence needed to apply that contract to a finding.

## Current Capability Gap

The existing cleanup skill is already strong on structural defects, recursive
configuration correctness, custom code, consent/routing evidence, duplicate
objects, and business-family conflicts. The missing capability is narrower and
important: it does not yet model reusable GTM architecture exhaustively enough
to identify valid-but-suboptimal designs.

| Area | Existing strength | Capability still needed |
| --- | --- | --- |
| Google configuration | `gtagConfig` is first-class and destinations, parameters, consent, and routing are inspected. | Distinguish Google tags, `gtagConfig` resources, Configuration Settings variables, Event Settings variables, inline values, inherited values, and per-tag overrides; compute the effective value for every consumer. |
| Event parameters | Each tag's values, types, ecommerce fields, and recursive sources are checked. | Index repeated inline parameters across compatible Google/GA4 tags and decide when an Event Settings variable is a real improvement. |
| Configuration parameters | Configuration fields and server routes are checked for correctness. | Detect coherent repeated configuration-level settings and decide when a Configuration Settings variable should own them. |
| Triggers and blockers | Exact/near/subset trigger candidates, multiple firing routes, malformed logic, groups, and some ineffective blockers are already detected. | Build one effective eligibility model per tag and judge redundant OR routes, reusable positive triggers, reusable exclusions, blocker intersection, and product-aware consent controls. |
| Firing priority | Priority is retained as route/execution metadata and official mechanics are referenced. | Review every explicit value; distinguish inert or unjustified ordering from a real same-event start-order requirement, and reject its use as an asynchronous completion mechanism. |
| CMP lifecycle and permission control | Didomi/OneTrust names and consent routes can be detected. | Add vendor-versioned event/variable semantics; classify consent infrastructure, confirmed Advanced Consent Mode, pure transporters, and direct non-Advanced routes; separate positive event eligibility from the mandatory reusable denial blocker for the last class; and model readiness, repeat, idempotence, replay, and canonical server forwarding. |
| Variables | Recursive sources, types, consumers, duplicate terminal sources, and shared inputs are reviewed. | Evaluate the complete reuse ladder: direct mapping, stable constant, shared settings, deterministic LUT/RLT, narrow transformation, and native/template replacement. |
| Architecture | Duplicates, overlaps, families, canonical survivors, and target states are reviewed. | Require an explicit optimisation conclusion for reusable settings, control topology, ownership, and change-surface reduction—not only duplication and conflict. |
| Tests | Defect, adversarial, mutation, and workbook coverage is extensive. | Add source-authentic positive and negative optimisation fixtures and prove that candidates are found without flattening meaningful differences. |

The lighter `gtm-container-audit-optimize` skill already expresses useful
conceptual criteria for simplification, shared settings, trigger architecture,
and target state. Those criteria are a benchmark, not a workflow to copy. The
target workflow below is justified independently; do not inherit the lighter
skill's scan structure or fixed workbook contract.

## Consolidated v1.13 Capability Disposition

The new design preserves useful analytical outcomes without copying v1.13 run
names, schemas, validators, workbook tabs, or implementation structure. Treat the
following as the behavioural migration contract:

| Capability cluster | Target disposition | Consolidated target requirement |
| --- | --- | --- |
| Source, skill, and context identity | Retain and strengthen | Accept only one complete unambiguous ContainerVersion or equivalent evidence set; validate every entity layer and unique ID; preserve wrapper and source coordinates; recognize documented built-in aliases and registered system IDs; separate supplied, inferred, confirmed-empty, and unresolved context; resolve executable `do_not_touch` scope to exact `layer:ID`; and lock source, context, skill, criteria, and contract versions before semantic work. |
| Deterministic evidence and completeness | Consolidate | Replace the old module/run-specific ledgers with one typed obligation ledger. Account exactly once for every object, configured leaf and branch, recursive source trace, cross-object consumer/peer contract, executable code segment, generated relationship, singleton, family, and container-level method, or record a source-counted zero/not-applicable result. Deterministic facts never become verdicts. |
| Operational sanitation and configuration correctness | Retain and extend | Preserve detection of broken or ambiguous references, lifecycle and reachability problems, duplicate and conflicting logic, trigger/group/sequence/schedule/firing defects, naming and folder problems, Zones, Google configuration resources, variables, consent routes, destinations, transformations, clients, templates, and domain-specific field/type/shape/timing errors. Express them through the 27-area contract instead of 48 legacy module interfaces. |
| Custom code and templates | Retain and generalise | Cover every executable nonblank line through stable source segments and behaviour blocks; record parser availability and parse limits; preserve source-visible control flow, return/type/null paths, side effects, network/DOM/storage/listener behaviour, security/privacy signals, and native/template/dataLayer/site-side replacement criteria. One segment cannot attest another, and a parser limit cannot become a clean verdict. |
| Vendor and product contracts | Retain and simplify ownership | Use one versioned registry of official product/template/CMP/vendor contracts. Each unknown identity receives one canonical research owner and dependent objects link to it. Bind the official domain, access date, applicable version, and supported rule before rebuilding affected obligations; metadata, comments, help URLs, and licenses do not create vendor identities. |
| Approved external requirements | Adapt to the new independence model | Normalize an analyst-approved tracking plan or equivalent requirement with exact file/sheet/row/raw-field hashes and label it as external requirement evidence. Exclude it from container-derived scan facts, assurance, and both audits' source-only discovery checkpoint. Release the same locked artifact to Audit A and Audit B only after each checkpoint; exact identifiers may create comparison obligations, but similar wording cannot infer a match or override container facts. |
| Consent and client/server routing | Strengthen | Replace scattered legacy checks with the four-class consent and routing decision model, effective eligibility, mandatory direct-route blocker architecture, confirmed Advanced Consent Mode criteria, pure-transporter forwarding contract, mixed-route split, and explicit unseen-server boundary. Preserve valid regional/default-writer and intrinsic built-in behaviour distinctions. |
| Business architecture and open discovery | Retain and strengthen | Preserve deterministic relationship candidates, singletons, complete member chains, source-visible retained distinctions, canonical ownership, and candidate-independent open discovery. Add valid-but-non-optimal reuse, ownership, control-topology, and change-surface conclusions. |
| Independent semantic review | Replace | Retire the three complementary run schemas. Every semantic obligation is judged by both isolated clean-room audits, with targeted neutral verification under the decided risk contract. Do not retain a three-run compatibility mode. |
| Sharding, sealing, and repair | Adapt | Shard only complete implementation families using a deterministic workload estimate and a shared-infrastructure unit; preserve exact hashes, prohibited-input checks, immutable seals, append-only fresh-context amendments, and lossless scratch recovery. Do not preserve v1.13's fixed row thresholds or legacy micro-shard formats. |
| Target state and operations | Retain within audit scope | Preserve exact creates, updates, remaps, override removals, renames, pauses, deletions, prerequisites, dependency order, behaviour/consent/routing preservation, static verification, rollback, and projected-container closure. Stop at a decision-ready plan; do not include execution machinery in this phase. |
| Decision calibration | Simplify | Use one evidence-based priority for ordering analyst attention and one evidence-confidence field for claim strength. Do not retain a separate severity scale unless forward-testing proves that it changes a user decision that priority and finding type cannot express. |
| Agent/runtime portability | Retain at the artifact-contract level | Keep source locks, bundles, seals, ledgers, canonical JSON, and workbook gates independent of one model's private reasoning. Provider-specific orchestration may differ, but an environment that cannot provide two isolated audits, deterministic scripts, or mandatory XLSX gates must block rather than use a same-context or reduced-depth fallback. |
| Human and technical delivery | Replace with a simpler current product | Deliver one purpose-built analyst workbook backed by one sealed canonical JSON record and manifest. Preserve exact row coverage, technical identifiers, evidence limits, privacy, formula safety, no truncation, and repairable presentation gates; retire the copied canonical-plus-analyst workbook structure. |

Before cutover, maintain one compact capability migration ledger that maps each
existing behavioural detector and regression fixture to exactly one outcome:
`retained`, `strengthened`, `consolidated into`, `deliberately deferred`, or
`obsolete implementation contract removed`. A retained or strengthened behaviour
needs a target-design fixture and observable assertion. The ledger maps behaviour,
not old filenames or schema fields, and must not create compatibility code.

The following utilities are deliberately outside this phase: row-level approval
packets, GTM/API/MCP mutation, import JSON generation/application, execution
preflight and drift checks, post-change readback certification, change-log
generation, and audit-to-audit delta reporting. Their removal from the target
runtime is an explicit scope decision, not permission to implement a reduced or
uncertified form. They may return only as complete future vertical slices.

## Semantic Capability Backlog

### SEM-001 — Complete the “what is wrong” model

**Priority:** Product P0

Before generating more optimisation advice, close the correctness gaps around
effective settings and control inheritance.

The neutral evidence layer must distinguish and connect:

- the Google tag template instance;
- an exported `gtagConfig` resource;
- a Google tag: Configuration Settings variable;
- a Google tag: Event Settings variable;
- a GA4/Google event tag's inline configuration and event parameters;
- inherited values and explicit tag-level overrides;
- configured destinations, connected-destination evidence boundaries, and
  browser-to-server routing;
- firing triggers, blocking/exception triggers, additional consent checks,
  built-in consent behaviour, sequencing, firing options, schedules, and
  priority;
- CMP event and variable contracts, including vendor/version, initialization
  point, consent-state availability, repeat-on-change behaviour, and exact ID
  matching; and
- every observed client-side consent mechanism on each tag: intrinsic product
  behaviour, Additional Consent Checks, positive-trigger conditions, reusable
  blockers, CMP/site code, and consent-forwarding configuration; and
- the selected route class and canonical target consent owner under the final
  consent-and-routing decision model.

For every effective field, retain the source object/path, configured value or
variable reference, recursive terminal source, type/shape, lifetime, consumers,
inheritance source, override state, destination/product context, consent/route,
and unresolved boundary.

**Defect criteria include:**

- missing or ambiguous settings-variable references;
- incompatible inherited type, shape, timing, or product support;
- conflicting inline override versus shared setting without an evidenced reason;
- duplicate or conflicting initialization and page-view ownership;
- inconsistent transport, destination, consent, or event settings across a route
  that claims one shared owner;
- ineffective or overbroad control topology proven by the configured trigger
  logic; and
- priority used as if it guaranteed asynchronous completion, consent state read
  before it is available, or a repeated CMP event that can duplicate a
  non-idempotent tag; and
- settings whose official product contract is visibly violated.

**Acceptance criteria:**

- every Google/GA4 tag exposes its effective settings, not merely its local
  parameter list;
- a Correct verdict closes inherited values and overrides explicitly;
- `gtagConfig`, tag, and variable resources are never treated as synonyms;
- external connected-destination settings remain an evidence boundary;
- every tag has one explicit consent-control classification, including a stated
  evidence limit when the container cannot prove the owner; and
- positive and negative fixtures prove each defect criterion.

### SEM-002 — Add a neutral optimisation fact layer

**Priority:** Product P0

Scripts should generate facts and candidates, not automatic recommendations.
Add deterministic indexes for:

- parameter occurrences by semantic level, key, value/source expression,
  type/shape, timing, destination/product, consent/route, and consumer;
- effective inherited values and local overrides per Google/GA4 tag;
- tag role and ownership: configuration/loader, event/action, helper, consent
  writer, linker, or transporter;
- normalized trigger event scope, condition set, firing consumers, blocker
  consumers, effective eligibility expression, lifecycle role, repeatability,
  and consent-state availability;
- exact, subset, superset, overlapping, and disjoint trigger routes;
- explicit priority values, possible same-event competitors, sequence edges,
  firing options, and any source-visible order rationale;
- CMP contracts by vendor/version: readiness, initial-state, update, and
  combined events; consent variables; token format; and vendor/purpose/category
  semantics;
- repeated terminal variable sources, mappings, transformations, constants,
  endpoints, IDs, consent helpers, and custom-code behaviour;
- destination, page-view, event-family, loader, consent, and server-route owners;
  and
- current object count/change surface versus the proposed target's objects,
  remaps, overrides, and retired copies.

Candidate generation is the minimum queue. A fresh architecture review still
performs open discovery and may reject every generated candidate when the source
proves a meaningful distinction.

**Acceptance criteria:**

- candidate generation is deterministic and judgment-free;
- each candidate cites all consumers and all potentially distinguishing facts;
- no candidate label is itself a finding;
- current and proposed change surfaces can be compared without a subjective
  “cleaner” claim;
- the fact layer remains independent of another review's verdicts.

### SEM-003 — Define Google tag and shared-settings optimisation criteria

**Priority:** Product P0

Google currently supports reusable Configuration Settings variables across
Google tags and reusable Event Settings variables across Google tags and GA4
Event tags. Tags can inherit those settings and keep explicit local overrides.
The skill must evaluate that architecture directly.

#### Configuration Settings candidate

Propose a Configuration Settings variable only when:

- at least two compatible Google tags repeat the same configuration-level key;
- the effective value or source expression, type, lifetime, destination/product
  applicability, route, consent contract, and intended ownership align;
- the field is genuinely configuration-level rather than event-specific;
- one shared owner reduces independently maintained copies without creating a
  broad coupling boundary; and
- every necessary exception can remain as an explicit, source-justified local
  override.

Typical source-visible candidates may include stable language/content context,
server container URL, cookie/configuration policy, groups/routing, or another
officially supported configuration parameter. Their presence alone never proves
they should be shared.

#### Event Settings candidate

Propose an Event Settings variable only when:

- at least two compatible Google or GA4 event tags repeat the same event-level
  parameter or user-property contract;
- the source, type/shape, event-time availability, destination/product support,
  consent, and intended consumer set align;
- the parameter has the same semantic meaning for every proposed consumer; and
- sharing does not hide event-specific ownership.

Keep transaction IDs, items, event values, search terms, form values, product
details, and similar event-specific data local unless the proposed variable is
deliberately scoped to a compatible event family and all source/timing semantics
are proven identical. A repeated parameter name alone is never enough.

#### Redundant and conflicting overrides

- An inline value identical to its inherited effective value is a removal
  candidate when deleting it preserves the same result.
- A differing override is retained when its event, destination, route, consent,
  market, product, or owner distinction is source-visible.
- A differing override with no supported distinction is a conflict or owner
  decision, not an automatic overwrite.
- A settings variable used by only one tag is not automatically wrong; require a
  concrete maintenance or ownership reason before recommending inlining.

#### Exact operation

An actionable sharing proposal identifies the new or canonical settings
variable, complete parameter set, every consumer assignment, every retained
override, every removed inline field, operation order, static effective-value
comparison, and rollback. Do not create the shared object until its complete
current-schema export representation is known from authentic evidence.

### SEM-004 — Define trigger and blocking-trigger optimisation criteria

**Priority:** Product P0

Model each tag's configured control topology before judging it:

```text
eligible event = (firing route 1 OR firing route 2 OR ...)
                 AND NOT (matching blocker 1 OR matching blocker 2 OR ...)
```

Conditions inside one trigger are conjunctive. A tag invoked through sequencing
must be judged under sequence semantics because its own firing triggers do not
control that invocation.

Before a verdict, capture:

- the tag's role: page/load initialization, business event/action, helper,
  consent writer, or transport;
- every positive event, filter, blocker, sequence route, firing option, schedule,
  and explicit priority;
- whether each event is one-shot, repeatable, or consent-change driven and
  whether required event data remains available on a later event;
- the CMP vendor/version, exact event and variable contract, consent-state
  availability, token format, and vendor/purpose/category semantics;
- the tag product's intrinsic consent capability, configured consent mode, and
  direct-browser versus client-to-server route; and
- whether the route is consent infrastructure, confirmed Advanced Consent Mode,
  a pure transporter with server-owned consent, or a direct non-Advanced route
  with blocker-owned consent.

#### Defect criteria

- duplicate firing routes can produce the same tag eligibility with no distinct
  event, scope, timing, or owner purpose;
- one firing route is fully subsumed by another on the same tag;
- a blocker cannot intersect any firing route's event scope;
- a broad blocker suppresses legitimate routes outside its evidenced policy;
- repeated positive/negative conditions contradict or make a route impossible;
- a trigger group, sequence, schedule, firing option, or priority changes the
  intended control semantics incorrectly; or
- consent control conflicts with the route's selected class and canonical owner
  under the final consent-and-routing decision model.

#### Firing priority

Treat every explicitly stored firing priority as a deterministic review
candidate. GTM's default is `0`; an explicit `0` adds no ordering information,
while a higher value only starts an eligible tag before lower-priority tags on
the same event. Tags still run asynchronously.

- Classify priority as a defect when it is used to claim completion, to order
  different lifecycle events, or to compensate for an incorrect trigger.
- Classify it as an optimisation opportunity when no other tag can be eligible
  on the same event, when an explicit `0` adds no information, when sequencing
  already owns the order, or when no source-visible start-order requirement
  distinguishes the tag from its competitors.
- Retain it only when at least one potentially co-eligible tag exists and a
  concrete start-order requirement—not completion dependency—is evidenced.
- When completion dependency is real, assess the simplest correct lifecycle or
  sequencing design separately; do not mechanically replace priority with
  sequencing.
- An action-ready removal names the affected tag and normalizes priority to the
  current-schema default/omitted representation. It also proves that triggers,
  sequencing, and all other advanced settings are unchanged.

#### Required direct-browser blocking architecture

For every direct browser/vendor route other than confirmed Advanced Consent Mode,
including Google tags that are not confirmed Advanced, keep business/readiness
eligibility and permission control separate:

```text
page/load tag = relevant CMP lifecycle event
                AND NOT reusable vendor/purpose/category denial blocker

later action tag = business custom event
                   AND NOT reusable vendor/purpose/category denial blocker
```

The positive firing trigger expresses only the event, timing, page, and business
scope. It must not repeat the consent condition. The exception/blocking trigger
is the single reusable GTM permission gate and must evaluate on every event it is
intended to block. Prefer one vendor-level blocker when the CMP's vendor state
already includes all required purposes; use a purpose or category blocker only
when that is the actual CMP policy unit. Do not layer both when one already
subsumes the other.

The target blocker must:

- fail closed for absent, unknown, or denied state under the proven GTM/CMP
  value contract;
- use exact token boundaries so one vendor or category ID cannot partially match
  another;
- intersect every protected firing route, including custom events; and
- have a consumer set that exactly matches the evidenced policy.

Do not duplicate this blocker with tag-level positive consent conditions or
Additional Consent Checks. "Built-In Consent Checks" describe intrinsic template
or product behaviour, not a configurable permission gate: record them, do not try
to disable them, and do not treat them as a substitute for the mandatory blocker.

A positive trigger that includes a consent-granted condition is an architecture
defect under the decided target, even when its present event set appears
equivalent. The repair must still prove current-versus-target event eligibility,
ordering, repeat behaviour, idempotence, and replay consequences before the
operation enters the final recommendation plan.

#### Product capability matrix

| Route class | Positive trigger | Consent-control owner | Agent decision |
|---|---|---|---|
| Consent infrastructure | Consent Initialization or documented CMP default/update event | The consent writer | Preserve the writer as ungated infrastructure and prove that defaults precede dependent tags. |
| Confirmed Advanced Consent Mode | Normal business/lifecycle event with no consent-granted condition | Coherent defaults/updates plus intrinsic product behaviour | Remove manual blockers and Additional Consent Checks; capability alone is insufficient to enter this class. |
| Pure client-to-server transporter | Normal business/lifecycle event with no consent-granted condition | One canonical consent value forwarded to server-owned vendor gates | Remove client consent blockers, positive consent conditions, and Additional Consent Checks only after proving a pure route and complete inherited forwarding. |
| Every other direct browser/vendor route, including non-Advanced Google | Consent-free CMP timing/lifecycle event for page-load behaviour, or the real later business event | One reusable vendor/purpose/category denial blocker | Require the separated firing-plus-blocker pattern, exact fail-closed matching, and no duplicate Additional Consent Check. |

This matrix implements the authoritative consent-and-routing decision model above;
it is a technical architecture decision, not a legal conclusion.

#### Pure client-to-server transporter architecture

Grant the no-client-gating exception only when the tag is a pure transporter:

- no direct browser vendor script or request exists on the same route;
- the normal lifecycle or business trigger contains no consent condition;
- no consent blocker or Additional Consent Check gates the transport;
- one complete canonical consent-state variable has a proved terminal source,
  type, default, and update contract;
- the variable is configured once through the Google tag or shared setting and is
  inherited by every transported event; and
- every downstream vendor-specific permission decision is explicitly outside
  this web-container audit, regardless of whether the user has separate server
  evidence elsewhere.

A mixed route is not pure. Judge its direct branch under the mandatory blocker
policy. When the branches cannot be separated, use that direct-route policy for
the tag and raise the architecture split as the target-state decision.

#### CMP event contracts

Never choose an event because its name sounds like "ready" or "loaded". Resolve
the installed CMP and version against a maintained official-source registry.
The current OneTrust registry reference points to generic Google consent help and
cannot substantiate OneTrust event semantics; replace it with the official
OneTrust integration and event contracts before enabling these verdicts.

- **Didomi:** `didomi-ready` occurs once, but user status may still be unknown;
  `didomi-consent` occurs on initial load and again on consent changes; and
  `didomi-consent-changed` occurs only on changes. `didomiVendorsEnabled`
  includes a vendor only when its required purposes are enabled and uses
  comma-terminated IDs. For a direct non-Advanced page/load vendor tag that
  should run after either existing or newly granted consent, a condition-free
  `didomi-consent` firing trigger plus an exact `vendor-id,` denial blocker is a
  target candidate only when once-per-page or proved idempotent behavior prevents
  duplicate initialization. `didomi-ready` alone does not provide later replay.
- **OneTrust:** the current official contract identifies
  `OneTrustGroupsUpdated` as firing when the script loads and whenever consent is
  updated; `OnetrustActiveGroups` carries active category IDs. A condition-free
  `OneTrustGroupsUpdated` page/load trigger plus an exact inactive-category
  blocker is therefore a direct-browser target candidate, again with repeat
  behavior controlled. Do not substitute `OneTrustLoaded`, `OptanonLoaded`, or
  another event without proving its exact versioned semantics.

For a later click, form, ecommerce, or other business event, retain that custom
event as the positive trigger and apply the same reusable blocker. Prove that the
CMP state is available before the event. If the business event can occur first,
blocking may correctly fail closed but the past event will not automatically
replay after consent; report the loss/replay decision instead of inventing a
trigger group or moving consent into site code.

Repeated CMP events also require an explicit firing-option/idempotence decision.
A blocker controls whether the tag fires on the current event; it does not unload
an already initialized vendor, erase its state, or prove withdrawal behavior.
Those runtime effects remain an evidence boundary for this container-only skill.

#### Optimisation criteria

- consolidate triggers only when type, event identity, filters, timing,
  repeatability, consumers, and ownership are equivalent;
- prefer one reusable positive trigger when several tags intentionally share the
  complete same business eligibility rule;
- factor a repeated negative policy into a shared blocker only when the exclusion
  is stable, applies to all proposed consumers, can intersect every relevant
  firing route, and is clearer than repeated negative filters;
- keep positive business eligibility in firing triggers and use blockers for a
  genuine reusable exclusion policy, not to hide core event logic;
- preserve separate triggers when their owners, lifecycle, event type, timing,
  page/market/product scope, consent model, or debugging needs differ; and
- use a trigger group only for a real AND lifecycle whose member events and
  data requirements remain valid—not as a generic consolidation mechanism.

Every proposed trigger change must compare the current and target static event
sets, conditions, blockers, sequence routes, and consumers. If equivalence or an
intentional behavior change cannot be proven, keep a decision/evidence boundary.

**Acceptance criteria:**

- every explicit priority receives a deterministic candidate fact and a defect,
  optimisation, retained, owner-decision, or evidence-limit outcome;
- every consent-relevant tag is assigned to exactly one capability-matrix route,
  with the product and control owner cited;
- a direct-browser blocker recommendation proves event/CMP ordering, blocker
  intersection, exact ID matching, repeat behavior, firing option/idempotence,
  and replay consequences;
- every direct non-Advanced route has one reusable blocker, while confirmed
  Advanced routes and pure transporters have none; Built-In Consent Checks are
  recorded as intrinsic metadata and never confused with Additional checks;
- every transporter exception proves route purity, one canonical inherited
  consent value, and the downstream server evidence boundary;
- Didomi and OneTrust verdicts cite their current vendor-specific registry
  contracts rather than inferred event names; and
- positive, negative, and near-neighbour fixtures prove every branch above.

### SEM-005 — Complete the wider “what can be better” taxonomy

**Priority:** Product P1

Apply the same evidence standard beyond Google settings and triggers:

- **Tag architecture:** one understandable initialization/configuration owner,
  event/action owners, helper/linker role, route, and destination responsibility;
- **Variables:** prefer a direct compatible DLV/template mapping, then a stable
  constant, coherent shared setting, deterministic LUT/RLT, and only then narrow
  custom transformation when it is genuinely required;
- **Native/template replacement:** replace Custom HTML/CJS only after proving
  value, type, timing, side effects, consent, route, and consumer equivalence;
- **Destination architecture:** identify duplicate initialization, duplicate
  page-view/event ownership, connected-destination boundaries, browser/server
  overlap, and justified market/product variants;
- **Consent architecture:** distinguish consent writers, confirmed Advanced
  Consent Mode, mandatory reusable blockers for every direct non-Advanced route,
  intrinsic Built-In metadata, configurable Additional Consent Checks, pure
  transporters, canonical forwarded consent state, mixed routes, and the fixed
  downstream server evidence boundary;
- **Organisation:** rename, folder, and ownership changes follow canonical object
  selection and produce a maintenance benefit beyond cosmetic preference; and
- **Change surface:** prefer the target with fewer independently maintained
  definitions only when it remains understandable and does not create excessive
  coupling or a high-impact shared failure point.

Each taxonomy family requires both positive examples and near-neighbour examples
that must be retained.

### SEM-006 — Separate defect and optimisation decisions in the result

**Priority:** Product P1

Do not force valid-but-suboptimal architecture into an `Issue` verdict. The
eventual schema and workbook must preserve, at minimum:

- `decision_class`: defect, correct but materially non-optimal, justified as-is,
  owner decision, or container evidence limit;
- literal current behaviour and affected object keys;
- the exact criteria that passed or failed;
- concrete consequence or improvement benefit;
- meaningful distinctions that must be preserved;
- simplest target direction;
- exact operation when action-ready;
- priority and evidence confidence; and
- the static verification needed after the change.

A correctness defect may also unlock an optimisation, but reconciliation keeps
one root cause and one coherent operation chain. An optimisation is normally
Medium or Low unless the source proves a material active risk; tidiness alone
must not inflate priority.

### SEM-007 — Add authentic optimisation fixtures and adversarial tests

**Priority:** Product P0 before implementation claims completeness

The current package does not contain source-authentic examples of Configuration
Settings or Event Settings variables. Priority currently appears only as route
metadata, and no fixture family locks a versioned CMP lifecycle contract. Before
hard-coding type names, parameter paths, event semantics, or consent variables,
collect or construct fixtures from verified current GTM exports and official
vendor contracts.

The fixture family must include:

- repeated compatible configuration settings across multiple Google tags;
- one intentional local configuration override;
- repeated compatible event settings across selected GA4 event tags;
- identical parameter names with incompatible event meaning or timing;
- an existing shared variable plus redundant and intentional inline overrides;
- duplicate, subset, overlapping, and intentionally distinct firing triggers;
- one useful shared blocker and one blocker whose event scope cannot intersect;
- explicit priority `0`, nonzero priority with no same-event competitor,
  justified start-order priority, priority incorrectly used for completion, and
  a sequence whose semantics must remain distinct;
- a confirmed Advanced Consent Mode Google route with no blocker or Additional
  Consent Check, plus a capability-only Google neighbour that must not be
  misclassified as Advanced;
- a direct non-Advanced Google tag and a non-Google vendor tag that both require
  the reusable blocker, plus invalid positive-consent and Additional-check copies;
- a pure client-to-server transporter with one canonical inherited consent value
  and no client gate, plus missing, multiple, inline, partially inherited, and
  mixed direct/server neighbours that must not receive the exception;
- complete, incomplete, and inconsistent client-side server handoff neighbours,
  all of which must stop at the exact downstream evidence boundary;
- a Didomi page/load tag using `didomi-consent`, an exact vendor blocker, and a
  once-per-page/idempotence decision, plus near neighbours using `didomi-ready`
  and `didomi-consent-changed` that must not be treated as equivalent;
- a OneTrust page/load tag using `OneTrustGroupsUpdated` and an exact active-group
  blocker, plus an unsupported `OneTrustLoaded` assumption that must be rejected;
- a later business custom event with CMP state already available and the same
  event occurring before CMP readiness, with the no-replay boundary exposed;
- a vendor-level state that already folds required purposes and a genuine
  purpose/category-level policy, so redundant and necessary controls separate;
- a repeated CMP event with safe once-per-page/idempotent behavior and one that
  would duplicate initialization;
- sequencing and trigger-group cases that must not be flattened;
- direct DLV, constant, LUT/RLT, native-template, and necessary CJS neighbours;
  and
- exact create/remap/remove operations plus current-versus-target effective-value
  comparisons.

Tests must assert observable facts, candidate membership, decision invariants,
and operation safety—not exact prose.

### SEM-008 — Prove usefulness through independent forward-testing

**Priority:** Product P1

After the semantic model works end to end, give an independent analyst agent an
unseen realistic export without naming the expected opportunities. Evaluate:

- defects found and missed;
- valid optimisation opportunities found and missed;
- false-positive consolidation or sharing;
- preserved intentional differences;
- usefulness and exactness of the proposed target operations; and
- whether the workbook clearly separates “wrong”, “can be better”, “should stay”,
  “decision needed”, and “cannot be proved from this evidence”;
- whether a web analyst can understand each visible row without hidden proof or
  agent vocabulary; and
- whether the workbook makes the highest-value actions, owner decisions,
  preserved architecture, evidence boundary, and next step immediately clear.

Only observed failures should create additional rules or detectors.

## Decided Audit And Delivery Workflow

The target workflow is a **verified scan plus dual clean-room audit**. Audit
result quality and trustworthiness are the primary objective; delivery speed is
secondary. The design deliberately avoids both a single-review shortcut and a
configurable per-obligation reviewer mesh whose orchestration could itself omit
coverage or fail.

```text
locked source and context
  -> canonical deterministic scan
  -> independent raw-source scan assurance
  -> complete semantic obligation ledger
  -> Audit A and Audit B in parallel, fully isolated
  -> independent validation and immutable seal of both audits
  -> contradiction-aware reconciliation
  -> neutral verification of disagreements, one-sided findings, and material risk
  -> reconciled target-state synthesis and exact operations
  -> projected-container scan, assurance, and semantic closure to a fixed point
  -> sealed canonical decision and operation record
  -> evidence-locked human translation and workbook build
  -> independent readability, visual, integrity, and privacy gates
  -> one analyst-facing workbook plus the separate canonical technical record
  -> phase complete; no GTM mutation or post-execution artifact
```

### Why this design

| Candidate | Quality and trust assessment | Complexity and speed assessment | Decision |
| --- | --- | --- | --- |
| Current three complementary runs | Strong isolation, but the runs own different questions and therefore do not independently review every material semantic conclusion. | Fixed review and reconciliation overhead; current Run 2 is a likely critical-path bottleneck. | Replace after proof. |
| One integrated audit plus a challenger | Produces a coherent target, but the challenger is anchored by the first audit and cannot supply a clean independent result. | Fast and simple, but below the required trust level. | Reject. |
| Pure bottom-up and pure top-down full audits | Independent, but several of the 27 areas do not sensibly fit one of the two methods; forcing them creates artificial work and weak conclusions. | High duplicated work and difficult prompts. | Reject. |
| Adaptive reviewer count and method per obligation | Can concentrate review effort precisely, but the assignment engine becomes a second complex product whose mistakes can silently remove independent coverage. | Potentially fast, but too much configuration, routing, and failure surface for the present need. | Reject. |
| Three or more complete semantic audits | Adds redundancy, but the marginal protection is lower than a differently structured second audit plus neutral verification of actual risk and disagreement. | Highest recurring audit cost. | Reject as the default. |
| Two complete hybrid clean-room audits plus targeted neutral verification | Every semantic obligation receives two isolated judgments; different traversal order reduces correlated misses; material agreements and all disagreements receive a fresh neutral check. | Both audits run concurrently; no third full audit; the workflow has a small fixed number of understandable stages. | **Selected.** |

Two is not treated as a universal truth. It is the simplest fixed design that
provides genuine independent semantic review. Add a third review only for an
observed risk class or failure that the neutral verification contract cannot
cover; do not expose reviewer count as an aggressiveness option.

### Stage 1 — Evidence Gate

Accept only a complete, unambiguous export or equivalent source. Lock source,
context, skill, audit-contract, template/vendor-contract, and optional approved
requirement identities. If the user already named one exact source and outcome,
start without an otherwise redundant confirmation exchange only when there is
one resolvable artifact, no competing candidate source, its complete container
identity can be read, and the requested outcome is the full audit workbook. If
any of those conditions fails, confirm the source or outcome once. Only
ambiguous or partial source identity, an unmodelled entity layer, or missing
evidence that prevents a configuration judgment blocks the audit.

### Stage 2 — Canonical Scan And Independent Assurance

Run every `Scan` clause in the 27-area contract once. Produce source-coordinate-
bound facts for objects, leaves, references, consumers, terminal sources,
effective values, event and blocker topology, code, consent and routing,
destinations, chains, families, relationship candidates, applicability, and
coverage at object, chain, family, and container level. The scan may identify a
relationship or invariant; it may not author correctness, necessity,
consolidation, priority, or target-state judgments.

Use one separate assurance module that directly rereads the locked raw source and
recomputes critical invariants instead of merely checking output shape:

- entity counts, IDs, and source hashes;
- reference endpoints and consumers;
- recursive terminal sources;
- trigger IDs, event names, and blocker attachments;
- effective Google setting ownership;
- consent-control and client/server transport fields;
- destinations and route hosts;
- source-owned configured leaf, branch, recursive-trace, and cross-object
  consumer/peer identities when they create semantic obligations;
- custom-code object and segment identities, nonblank executable line ranges,
  segment hashes, and parser-coverage status;
- matched and unmatched vendor/host identities plus the deterministic canonical
  research owner assigned to each unknown identity;
- generated relationship-candidate IDs, exact members, comparison type,
  source coordinates, and owning obligation; and
- exact 27-area coverage-ledger membership.

A mismatch blocks semantic review. The assurance path may reuse low-level JSON
decoding, but it must not call the scanner's derived graph, normalisation, or
candidate-generation logic for an invariant it claims to recompute. Do not
maintain two complete competing scan engines: that would duplicate implementation
and allow the scanners to drift. Enable a specialised assurance check only when
its source mechanism or applicability rule is present, but require source-counted
proof of non-applicability rather than silently skipping it.

### How All 27 Areas Fit

Bottom-up and top-down are traversal orders inside each complete audit, not two
exclusive audit scopes:

| Method class | Audit areas | Required treatment in both clean-room audits |
| --- | --- | --- |
| Pre-audit evidence gate | 1 | Deterministic gate and independent assurance; no semantic vote. |
| Object/chain-first | 2, 3, 6, 8, 14, 17, 19, 22 | Inspect literal objects, fields, code, dependencies, contracts, and consumers first, then test the conclusion against family/container context. |
| Cross-level | 4, 5, 7, 9, 10, 11, 12, 13, 15, 16, 18, 20, 21, 23, 25 | Prove local configured behaviour and independently judge family/container ownership, necessity, reuse, and target architecture. Neither level may substitute for the other. |
| Container/family-first | 24, 26 | Decide canonical ownership and greenfield target architecture first, then prove every affected member and dependency against raw object evidence. |
| Post-reconciliation proof | 27 | Compile exact operations only from reconciled decisions, then simulate and validate them; pre-reconciliation reviewers may propose a target but not invent the final operation packet. |

This mapping accounts for the entire master list without pretending that source
identity is a top-down opinion or that exact operation ordering is a
pre-reconciliation audit verdict.

### Stage 3 — Audit A: Evidence-First Traversal

Audit A starts at objects and implementation chains, then expands to families and
the complete target architecture. It receives the locked source, independently
assured neutral facts, context, audit criteria, and applicable official
contracts. It must:

- complete every applicable `Audit` obligation in areas 2 through 26;
- answer what is wrong, what can be materially better, what should stay and why,
  and what remains an owner decision or evidence limit;
- prove every recursive source, consumer, trigger, consent, route, destination,
  and preservation constraint relevant to its conclusion;
- attest every object, chain, family, relationship candidate, singleton, and
  container-level method; and
- perform open discovery beyond generated candidates.

Before any approved external requirement evidence is released, Audit A seals a
source-only checkpoint of current configured behaviour, families, relationships,
and open discoveries. The later requirement comparison may add obligations or
narrow an evidence boundary, but it cannot rewrite that checkpoint.

### Stage 4 — Audit B: Target-First Traversal

Audit B runs concurrently in a separate fresh context and physical bundle. It
starts from destinations, consent/routing ownership, implementation families,
and the senior-from-empty target, then works down to every member, field,
dependency, and code path needed to prove or reject that architecture.

It receives the same locked source, context, audit contract, and official
contracts. It begins candidate-blind and external-requirement-blind: before
receiving generated relationship candidates, candidate-derived obligations, or
approved external requirement evidence, it must independently reconstruct and
checkpoint current configured behaviour, families, relationships, singletons,
and open discoveries from the raw source. Those inputs are released only
afterward for coverage closure and requirement comparison; they may add review
work but cannot replace or rewrite the checkpointed discovery map. Audit B then
completes the same semantic obligations and output schema as Audit A.

The different order creates useful methodological diversity without asking one
audit to use an unsuitable method. Audit A must still finish container-level
architecture; Audit B must still finish literal object and chain correctness.

### Isolation And Sealing Contract

Before reconciliation:

- each audit may read only its own allowlisted bundle and the common locked
  evidence contract; it cannot read the other audit's scratch files, verdicts,
  discoveries, rationales, proposed targets, or operations;
- each uses a distinct reasoning-context identity and physical allowlist;
- the orchestrator coordinates but authors neither audit;
- each audit has its own exact coverage validator and may be sharded only by
  complete implementation families with a dedicated shared-infrastructure unit;
- the package records one deterministic workload estimate from object,
  obligation, relationship, code-segment, and shared-dependency counts and uses a
  release-tested schema ceiling to choose single-file or family-sharded work;
  analysts cannot lower evidence scope or reviewer count to fit a context;
- all shards remain inside their audit and cannot see foreign-audit output;
- after shard completion, each audit performs one global closure pass across
  cross-family dependencies, shared configuration, consent, routing,
  destinations, identity, and architecture, and seals one coherent verdict set;
- each completed audit is immutable and hash-sealed; and
- reconciliation cannot start until both seals and all coverage obligations pass.

If two distinct contexts and physical allowlists are unavailable, the certified
audit is blocked; there is no same-context or shared-scratch fallback. An audit
amendment uses a fresh context bound to the prior seal, archives the prior seal
and exact artifact in an append-only history, and never exposes the other audit's
conclusion. Undeclared scratch is moved to that audit's declared scratch area and
recorded rather than deleted; changed declared input still blocks resealing.

### Stage 5 — Reconciliation And Neutral Verification

Reconcile decisions by exact source obligation, object set, family, relationship,
and target—not by similar wording. First decompose combined findings into atomic
claims; every atom present in only one audit is a one-sided finding even when the
larger conclusions are compatible. Classify each comparison as agreement,
compatible complementary conclusions, one-sided finding, conflicting verdict,
conflicting target, or different evidence boundary. Do not vote, average, merge
unmatched claims without verification, or silently prefer one audit.

A fresh neutral verifier is mandatory for:

- every disagreement or one-sided finding;
- every consent architecture or consent-owner conclusion;
- client/server transport or server-consent changes;
- active deletion or consolidation;
- loader, destination, page-view, ecommerce, paid-media, or identity changes;
- Custom HTML, Custom JavaScript, or template replacement;
- high-fan-out shared settings and cross-market changes;
- unknown integrations; and
- every projected High or Critical operation, even when both audits agree.

The verifier receives exact raw coordinates, independently reconstructed neutral
facts, the applicable contract, and a neutral question. It does not receive audit
identities, rationales, vote counts, or an expected result. It may confirm,
narrow, reject, or leave the decision blocked.

### Stage 6 — Target Synthesis, Operations, And Fixed Point

Only reconciled and, where required, neutrally verified decisions may enter target
synthesis. Build one coherent container architecture, then compile exact creates,
changes, remaps, renames, pauses, deletions, dependencies, static verification,
and rollback. The synthesiser cannot introduce a new semantic choice. Any newly
proposed consolidation, owner, route, or behaviour change receives two fresh
isolated reviews before it can enter the packet.

Apply the packet to a complete copy. Rerun the canonical scan and independent
assurance globally, regenerate obligations and relationship candidates, and send
every new semantic obligation through two fresh isolated reviews. Add deterministic
orphan closure only from the projected consumer graph.

Use a deterministic closure protocol:

1. Each full projection cycle starts again from the locked original source and
   applies the complete current operation packet in dependency order.
2. Record the projected graph, scan-fact, obligation-set, relationship-candidate,
   decision, and operation-packet hashes for that cycle.
3. A cycle passes only when it creates no new or changed actionable obligation,
   every prior operation still resolves its source decision, every owner decision
   or evidence limit remains explicitly bounded, and scan plus assurance pass.
4. Replay a passing packet once from the locked original source. The replay must
   reproduce all projected hashes exactly before sealing.
5. Allow at most three full projection cycles, including the first. Block as
   `non_convergent_target_state` when the third cycle is not stable, a previous
   hash tuple recurs with an unresolved actionable obligation, a field/object
   target oscillates, or a new obligation has no exact safe operation.

The cycle limit is fixed, not configurable. A blocked result requires target-
architecture correction; it must not be bypassed by dropping an obligation or
loosening assurance. After a passing deterministic replay, seal the canonical
machine record. That record, not presentation prose, is the authority for every
audit decision, target operation, and workbook row.

### Stage 7 — Evidence-Locked Human Delivery

Human delivery is a separate presentation transformation after audit closure,
not another audit lens. Build one purpose-built analyst workbook directly from
the sealed canonical record. Do not copy a technical workbook and add a second
set of human tabs: duplicated plans create competing surfaces and make it unclear
which rows the user should review and decide on. Keep the canonical JSON record and
its manifest as the separate lossless technical and recovery artifact.

Use this bounded delivery path:

1. A deterministic delivery mapper assigns each canonical record type to one
   owning sheet and each record to exactly one primary row of that type. Other
   sheets may link to that row but may not duplicate its prose or create a second
   decision surface.
2. A completeness gate requires the canonical record to supply the current
   configured behaviour, decision class, concrete consequence or benefit,
   preserved distinctions, target direction, evidence confidence, and next step.
   A missing field stops delivery and returns that exact record to its owning
   audit. Reopen only that audit in a fresh amendment context bound to its prior
   seal, rerun exact reconciliation and any required neutral verification,
   repeat projected-state closure, and reseal the canonical record. The delivery
   writer and builder may never patch, infer, or directly edit a canonical field.
3. A fresh editorial context receives only row-bound reconciled evidence and an
   audience/language brief. It may edit declared prose fields, but it cannot
   change IDs, object keys, decision class, priority, confidence, evidence
   boundary, target direction, operation content, dependencies, decision unit,
   verification, or rollback.
4. A deterministic builder creates the workbook and verifies exact row coverage,
   locked-field equality, links, formulas, notes, redaction, and source/record
   hashes. A recovery check rebuilds the workbook using only the sealed canonical
   record, manifest, and completed editorial artifact and requires identical
   normalized sheet, cell, formula, note, hyperlink, and dimension content.
5. Run two focused fresh-context checks in parallel. The fidelity verifier
   compares every human row with its bound canonical record and rejects changed
   meaning, omitted caveats, overstated consequences, or mismatched actions. The
   reader receives only the workbook and audience brief, as a user would, and
   flags rows that are ambiguous, machine-oriented, non-standalone, repetitive,
   or unclear about the required next action. Neither checker may author or
   reverse a decision.
6. Apply only evidence-bound editorial corrections, rerun the integrity gate and
   the affected fidelity/readability checks, render every visible sheet, inspect
   layout and navigation, and run the final privacy/formula scan. If the corrected
   workbook still fails, delivery remains incomplete; do not weaken a claim, omit
   a row, or reopen an audit for a presentation-only defect. Reopen the owning
   audit chain only for a canonical semantic or completeness defect identified by
   step 2 or the fidelity verifier.

#### Human Workbook Structure

Use progressive disclosure so each audience can stop at the level it needs:

| Sheet | Primary user question | Required content |
| --- | --- | --- |
| `01 Overview` | What did the audit conclude and what should happen next? | Source and static scope, evidence boundary, status, counts by decision class and priority, highest-value actions, target-architecture summary, important retained families, blocking decisions, material before/after deltas, and one next step. |
| `02 Recommendations` | What exactly should I decide on or hand to implementation? | Every decision-ready atomic operation exactly once, grouped visually by coherent change family but retaining its stable operation ID. |
| `03 Decisions Needed` | What answer is required from an owner? | Every owner question exactly once, the analyst recommendation, why the answer is needed, affected scope/families, and what the answer unlocks. |
| `04 Full Audit` | What was checked, including configurations that should stay? | Every reconciled audit decision exactly once, including correction, optimisation, appropriate-as-configured, owner-decision, evidence-limit, and not-applicable outcomes. |
| `05 Custom Code` | What does each code object do and what is its safest target? | Every applicable Custom HTML, Custom JavaScript, or custom-template code conclusion once; omit the sheet only when the source count is zero and state that zero in `01 Overview`. |

`02 Recommendations` uses these visible columns:

1. `Action + operation ID`
2. `Finding type + priority`
3. `Affected scope`
4. `Current setup`
5. `Why it matters`
6. `Recommended target`
7. `Analyst decision / implementation handoff`
8. `Static verification / rollback`

Keep the controlled finding type and priority as separate bound values in the
canonical record while rendering them together in one filterable human column.
This preserves sorting and meaning without making the recommendation sheet wider
than necessary.

Use `Needs correction` and `Optimisation` as distinct action types. Keep exact
structured field paths, long before/after payloads, hashes, and dependency
packets in row-bound notes and the canonical record, while the visible row names
the actual GTM objects and complete change in analyst language.

`03 Decisions Needed` uses `Decision ID`, `Question`, `Why this is needed`,
`Recommendation`, `Affected scope`, and `What the answer unlocks`. `04 Full Audit`
uses `Audit ID`, `Area`, `Affected scope`, `Decision`, `Plain-language finding`,
`Outcome / linked action`, `Priority`, and `Evidence confidence`. Expand actions,
optimisations, decisions, and material evidence limits by default; retained and
not-applicable rows may be count-labelled and outline-collapsed, never omitted.

The workbook may support a human analyst decision such as proceed, reject, or
revise, but it is not an executable approval packet in this phase. A later GTM
implementation task must obtain and validate its own explicit authorisation and
must not treat workbook delivery alone as permission to mutate the container.

#### Information And Wording Contract

The workbook must remain complete without reading like an evidence dump:

- Translate canonical decision classes through one controlled human vocabulary:
  `Defect` becomes `Needs correction`; `Correct but materially non-optimal`
  becomes `Optimisation`; `Justified as-is` becomes `Appropriate as configured`;
  `Owner decision` becomes `Decision needed`; and `Container evidence limit`
  becomes `Cannot determine from container evidence`. Use `Not applicable` only
  for a source-counted coverage obligation that genuinely does not apply.
- Assume the primary user is a web analyst reviewing, challenging, approving,
  and potentially implementing the plan. Make `01 Overview` understandable to a
  marketing or business owner without removing the exact GTM detail needed by
  the analyst in later sheets.
- Level 1, `01 Overview`, supports prioritisation and orientation; Level 2,
  recommendations and decisions, supports the analyst's decision and implementation
  handoff; Level 3, the full audit and
  code review, supports analyst challenge; the canonical record holds exhaustive
  technical proof.
- Lead with the current configured situation, then state the concrete consequence
  or improvement benefit, the recommended target, and what important behaviour
  remains unchanged. Do not begin with a JSON field or internal rule name.
- Describe an optimisation through its concrete simplification or drift-reduction
  benefit, not as a disguised defect. For an appropriate configuration, name the
  exact distinction that justifies retention. For a decision or evidence limit,
  state the one missing answer or proof and the next responsible step.
- Use ordinary web-analyst language. Never expose terms such as semantic
  obligation, scan candidate, clean-room run, seal, reconciliation class,
  challenge context, parser trace, validator, or source hash in visible prose.
- Preserve exact GTM object names, IDs, event names, parameter names, destination
  IDs, consent tokens, and operation IDs. Explain necessary technical terms once;
  do not translate or paraphrase identifiers.
- Distinguish source-visible fact from expected consequence. Use explicit limits
  such as “the container export shows” and “runtime behaviour cannot be confirmed
  from this audit” instead of implying live firing, vendor receipt, legal
  compliance, or guaranteed measurement preservation.
- Reject vague instructions such as “review configuration”, “optimise tag”, or
  “fix consent”. Every action or decision states the object scope, exact target,
  and next responsible step.
- Avoid repeated boilerplate and false precision. Do not use health scores,
  invented savings, invented implementation time, or unsupported risk claims.
- Use the language requested by the user, defaulting to English. Localisation may
  change headings and prose only, never source-authored values or technical IDs.
- Use accessible styles, textual status labels in addition to colour, filters,
  frozen headers, wrapped top-aligned cells, stable widths, outline groups, and
  internal links. Do not merge data cells, clip or silently truncate content, or
  rely on cell colour to carry meaning.

### Speed Without Weakening Trust

The workflow improves time to result through bounded, auditable mechanisms:

- Audit A and Audit B execute in parallel;
- large audits shard by complete implementation family inside each isolated
  audit, so the largest configuration review is not one serial bottleneck;
- deterministic facts and official-source registry records are built once;
- the assurance path recomputes only critical invariants rather than duplicating
  the complete scanner;
- a third complete audit is replaced by targeted neutral verification;
- validators run per completed shard and only a failing shard is amended;
- unchanged source-bound scan artifacts resume only when source, context,
  contract, scanner, and registry hashes all match;
- reviewers author judgments and preserved distinctions, not repeated factual
  narration already present in the evidence package; and
- the delivery mapper runs once from the sealed record, editorial rows may be
  rewritten in parallel, and a presentation-only failure repairs only affected
  delivery rows before rebuilding the one analyst workbook.

No speed optimisation may reduce obligation coverage, allow one audit to see the
other, turn an unresolved judgment into a deterministic fact, or skip projected-
state closure.

### Workflow Replacement Proof Gate

The current release remains the operational baseline until the selected workflow
passes an independent no-cheat comparison on unseen representative web and, when
applicable, server evidence. Quality is evaluated before speed.

Compare the target against the in-scope behavioural capabilities in the
consolidated disposition, not against obsolete run/workbook schemas or deliberately
deferred downstream utilities. A deferred utility passes only by being absent and
clearly out of scope; a partial or uncertified replacement fails.

The replacement must prove:

1. complete source and 27-area scan coverage, including source-counted zero and
   not-applicable evidence, plus independent assurance of every applicable
   critical identity listed in Stage 2;
2. complete object, chain, family, relationship, singleton, and container
   semantic coverage in each clean-room audit;
3. distinct context identities, prohibited-input enforcement, and no foreign
   verdict access before both seals;
4. detection of all seeded material defects and valid optimisation opportunities,
   preservation of every intentional near-neighbour, and no increase in
   unsupported cleanup advice;
5. correct surfacing and neutral handling of disagreements, one-sided findings,
   high-risk agreements, and evidence limits;
6. exact action completeness, dependency-safe operations, and a passing
   projected-container fixed-point gate, including deterministic replay and
   correct blocking of non-convergent or oscillating targets;
7. canonical-record completeness and a repair test proving that a semantic gap
   reopens the owning audit/reconciliation chain and reseals it rather than being
   patched by delivery code;
8. an analyst deliverable whose visible claims remain bound to the canonical
   decisions and operations; and
9. exact human-delivery row coverage, zero locked-field drift, standalone reader
   comprehension, visible distinction among decision classes, and passing
   canonical-record workbook recovery, rendered-layout, privacy, and
   formula-injection checks; and
10. a complete capability migration ledger and equal-or-better confirmed finding
    recall, false-positive rate, target-state coherence, and static operation
    safety than the current release for every retained or strengthened behaviour.

Only after all quality gates pass should the comparison consider wall-clock time,
semantic work units/tokens, shard amendment rate, reconciliation conflicts,
simulation iterations, and workbook build time. If adopted, replace the old
three-run workflow and copied-canonical dual-workbook delivery path, then remove
their obsolete schemas, scripts, validators, references, and all deferred-utility
runtime paths. Do not ship both workflows, two competing human plans, a
compatibility mode, a reduced audit fallback, or dormant execution/change-log
machinery.

## Current Official Basis For This Phase

- [Reuse configuration settings in Google Tag Manager](https://support.google.com/tagmanager/answer/13438166)
- [Reuse event settings in Google Tag Manager](https://support.google.com/tagmanager/answer/13438771)
- [Set up Google Analytics in Tag Manager](https://support.google.com/tagmanager/answer/9442095)
- [Firing triggers and trigger exceptions](https://support.google.com/tagmanager/answer/7679318)
- [Tag firing priority](https://support.google.com/tagmanager/answer/2772421)
- [Unblock Google tags when using consent mode](https://support.google.com/tagmanager/answer/12962079)
  — evidence for the confirmed Advanced Consent Mode route only under this
  contract
- [Google Tag Manager `gtag_config` REST resource](https://developers.google.com/tag-platform/tag-manager/api/reference/rest/v2/accounts.containers.workspaces.gtag_config)
- [Didomi GTM integration](https://developers.didomi.io/cmp/web-sdk/third-parties/tags-management/tag-managers/google-tag-manager/configure-the-didomi-gtm-integration)
- [Didomi events and variables](https://developers.didomi.io/cmp/web-sdk/third-parties/tags-management/events-and-variables)
- [Didomi custom-event ordering](https://developers.didomi.io/cmp/web-sdk/third-parties/tags-management/events-and-variables/custom-events)
- [OneTrust GTM integration](https://my.onetrust.com/articles/en_US/Knowledge/UUID-301b21c8-a73a-05e8-175a-36c9036728dc)
- [OneTrust Web CMP events](https://developer.onetrust.com/onetrust/docs/javascript-events-guide)

Re-resolve version-sensitive product semantics against current official Google,
Didomi, and OneTrust documentation when the skill is implemented or released.

## Engineering Optimisation Backlog

The following engineering improvements remain valid, but the semantic capability
phase above is now the product priority. Do not begin a broad internal refactor
until the new evidence and decision contract identifies the stable module seams.

### EVO-001 — Remove obsolete package and schema compatibility paths

**Priority:** Engineering P0 after the semantic capability phase

**Finding:** The project rule forbids backward-compatibility layers, fallbacks,
and migrations, while the skill still explicitly supports legacy review-package
shapes and resumability paths.

Confirmed examples include:

- legacy review-shard support from the former v1 runtime;
- low-level compatibility retained by the former shared v1 review validator
  (removed in the v2 implementation);
- legacy manual-sharding instructions in the former execution contract and
  `references/02-commands/validation-commands.md`;
- a recognized legacy workbook shape in the former v1 delivery contract.

**Required evolution:** Establish one current package/schema contract, inspect
all callers, then remove obsolete compatibility branches, instructions, and
tests in the same change. Do not replace them with adapters, migrations, aliases,
or transitional fallback code.

**Important distinction:** Keep detection and analysis of legacy GTM objects,
Universal Analytics, obsolete tags, rollback objects, and migration-labelled
container content. That is source-domain evidence and part of the audit's job;
it is not backward compatibility in the skill implementation.

**Acceptance criteria:**

- one current review-package and workbook schema is authoritative;
- obsolete shapes fail with a clear unsupported-input error;
- no production branch exists only to support an obsolete internal package;
- the single target package shards, resumes, validates, merges, and seals
  correctly under its current family-based contract;
- legacy GTM configurations remain fully auditable.

### EVO-002 — Classify and eliminate ambiguous fallback behaviour

**Priority:** Engineering P0 after the semantic capability phase

**Finding:** The package uses “fallback” for several different concepts:

1. configured GTM fallback semantics that must be audited;
2. deterministic evidence methods used when parsing or grouping cannot use a
   preferred path;
3. legacy compatibility behaviour;
4. reduced-mode behaviour that the skill already correctly forbids.

Treating all four alike would damage the audit, but leaving them ambiguous makes
the project rule difficult to enforce.

**Required evolution:** Inventory each executable fallback and classify it.
Retain source-domain semantics. Remove compatibility fallbacks. When an alternate
method is required for complete evidence, define it as an explicit supported
analysis mode with its own contract and validation—or block if complete evidence
cannot be produced. Do not silently degrade.

**Acceptance criteria:**

- every executable alternate path has an explicit current requirement;
- no generic catch-all path can turn missing evidence into a clean verdict;
- terms such as “canonical grouping”, “raw-segment review”, or “blocked” replace
  “fallback” where those are the actual semantics;
- the no-reduced-audit invariant remains unchanged.

### EVO-003 — Make the runtime dependency contract unambiguous

**Priority:** P1

**Finding:** `pyproject.toml` declares `dependencies = []`, while `openpyxl` is
needed for the mandatory XLSX deliverables and is grouped with optional
`esprima` under the `analysis` extra. The documentation requires installing
`.[analysis,dev]`, but the package metadata does not clearly distinguish a
mandatory runtime dependency from an optional parser enhancement.

**Required evolution:** Declare `openpyxl` as a required runtime dependency
because XLSX delivery is mandatory. Keep `esprima` optional only while its
evidence-limit behaviour remains explicit and safe. Before adding any workbook
rendering package, inspect the existing runtime and libraries for a maintained
capability that can render every visible sheet reliably; add one new dependency
only if the existing stack cannot satisfy the tested rendering contract. Do not
preserve old extra names through aliases.

**Acceptance criteria:**

- a fresh environment following the documented install can produce every
  mandatory deliverable;
- `openpyxl` is installed by the normal runtime contract, not an optional
  analysis extra;
- required and optional dependencies are accurately labelled;
- missing optional parser support cannot be mistaken for complete parser proof;
- dependency declarations, installation instructions, and release tests agree.

### EVO-004 — Tighten progressive disclosure and sources of truth

**Priority:** P1

**Finding:** Routing is already strong, but the 238-line `SKILL.md` and 459-line
`README.md` repeat parts of the detailed contracts, commands, release history,
and workflow. The frontmatter description is accurate but long for automatic
skill discovery.

**Required evolution:** Keep only activation criteria, scope boundaries,
non-negotiable invariants, stage selection, and reference routing in `SKILL.md`.
Keep each detailed obligation in one authoritative reference. Tighten the
frontmatter description without broadening invocation. Retain a public README
only for repository-level use; move version history to release notes and avoid
duplicating normative contracts there.

**Acceptance criteria:**

- every normative rule has one authoritative home;
- all references remain discoverable from the entrypoint or their parent
  reference;
- the frontmatter remains discriminating for audit/optimisation requests and
  excludes runtime recette, legal decisions, GTM mutation, import application,
  version creation, publication, and post-execution certification;
- release checks confirm that no required resource became unreachable;
- removing duplicate prose does not remove an operational invariant.

### EVO-005 — Split oversized modules along existing domain seams

**Priority:** P1

**Finding:** The package is separated by domain at a high level, but several
modules carry too many responsibilities:

- `gtm_configuration_review.py`: 5,557 lines;
- `gtm_baseline_audit.py`: 3,968 lines;
- `gtm_operation_compile.py`: 3,936 lines;
- `gtm_workbook_readability.py`: 3,372 lines;
- `gtm_architecture_review.py`: 2,831 lines.

Large size alone is not a defect, but these modules are the clearest
maintainability risk and make focused validation harder.

**Required evolution:** Map responsibilities and import relationships first.
Extract only cohesive, already-existing concerns such as schema validation,
fact derivation, verdict validation, operation conflict analysis, and workbook
rendering. Keep command entrypoints thin. Do not introduce a framework, plugin
system, speculative abstraction, or compatibility wrapper merely to reduce line
counts.

**Acceptance criteria:**

- each extracted module has one clear reason to change;
- dependency direction is explicit and free of cycles;
- documented current commands either remain valid or are changed atomically
  with every caller and reference;
- behaviour-focused tests pass before and after each extraction;
- no duplicate implementation remains in old and new modules.

### EVO-006 — Modularise the test suite around behavioural contracts

**Priority:** P1

**Finding:** `tests/test_pipeline.py` is 8,929 lines. The suite is extensive and
valuable, but its concentration makes failures harder to localise and encourages
new cases to accumulate in one file.

**Required evolution:** Split tests by stable subsystem and invariant—for
example source identity, scan assurance, package construction, clean-room audit
isolation, review validation, reconciliation and neutral verification,
future-state safety, static operation safety, and workbook delivery. Share
fixtures only when they represent the same raw evidence, not merely to reduce
lines.

**Acceptance criteria:**

- all in-scope current behavioural assertions are retained or replaced by
  stronger target-design assertions;
- tests owned only by deliberately deferred utilities are removed atomically
  with those runtime paths and recorded in the capability migration ledger;
- no production test depends only on generated wording, headings, or regex text;
- the complete suite and coverage gate remain green;
- each regression has an obvious owning test module;
- production scripts do not import test helpers.

### EVO-007 — Turn forward-testing into observable release evidence

**Priority:** P1 for substantial behavioural changes; P2 otherwise

**Finding:** `references/02-commands/forward-test-prompts.md` defines a strong
215-line no-cheat protocol, but the static package does not prove that an
independent agent executed it against unseen evidence for the release.

**Required evolution:** For every substantial or safety-sensitive revision,
run a representative forward test in an isolated temporary workspace using a
fresh reasoning context, a neutral request, and the minimum unseen or synthetic
artifacts. Inspect each raw review before reconciliation. Keep concise release
evidence outside the shipped runtime package unless it is required by a release
gate.

**Acceptance criteria:**

- the evaluator is not given the suspected defect or intended answer;
- each review is independently inspected before the final plan;
- false positives, misses, and safety-blocking behaviour are recorded;
- observed failures produce narrow fixes and regression tests;
- the evaluation does not contact or mutate a live GTM container.

## Evolution Order

Implement the backlog in working vertical slices:

1. obtain source-authentic settings, priority, trigger, and CMP-control fixtures
   and complete the effective current-state correctness model;
2. add neutral optimisation facts and candidate generation for one vertical
   slice: Google shared settings plus trigger/control topology;
3. add evidence-bound agent criteria, result classification, exact operations,
   and adversarial tests for that slice;
4. align the target runtime dependency contract before implementing its mandatory
   workbook: make `openpyxl` required, verify the existing rendering capability,
   and add no rendering package unless the current stack fails the tested need;
5. carry that one slice through a thin but complete isolated target path:
   evidence lock, canonical scan and independent assurance, typed obligation
   ledger, Audit A and Audit B, reconciliation and required neutral verification,
   deterministic fixed-point closure, sealed canonical record, one analyst
   workbook, and all delivery gates;
6. no-cheat forward-test that end-to-end slice and correct observed semantic,
   interface, isolation, convergence, or human-delivery failures before adding
   another domain;
7. extend the same working target path one domain at a time to variables,
   native/template replacement, destinations, remaining consent architectures,
   organisation, custom code, vendor contracts, and the rest of the 27-area
   change surface; every added domain must reach a validated workbook before the
   next domain begins;
8. stress-test the complete target workflow on representative small and large
   containers, including family sharding, approved external requirements,
   non-convergence, sealed-record repair, source-counted zero, workbook-only
   comprehension, rendered layout, privacy, and presentation-failure cases;
9. after the complete replacement proof gate and capability migration ledger
   pass, atomically cut over and remove the obsolete three-run and
   copied-canonical dual-workbook schemas,
   scripts, validators, references, tests, and deliberately deferred utility
   paths;
10. resolve remaining obsolete schema/package compatibility and fallback
   classification;
11. refactor production and test modules one stable semantic boundary at a time.

### Why the thin end-to-end slice comes first

The prior sequence postponed the new workflow and delivery interfaces until most
semantic domains had already been expanded. A late discovery that the obligation
schema, clean-room bundles, reconciliation contract, convergence loop, canonical
record, or workbook mapping did not compose would force broad rework and could
trade a working baseline for unfinished complexity.

The thin path proves those long-term interfaces with one useful real domain while
change is still cheap. "Thin" limits development scope, not audit quality: it is
an isolated evaluation path and cannot be presented as a certified reduced audit.
The released v1.13 workflow remains the only runtime path until the full target
coverage and replacement gate pass. At cutover, remove the old path atomically so
the shipped skill again has one complete workflow and no compatibility mode.

Do not combine all refactors into one release. Before workflow cutover, each
slice must leave the released skill installable, testable, and capable of its
full current workflow while the target slice remains isolated from user-facing
invocation. The cutover itself must leave one complete target workflow; do not
retain old and new runtime paths in parallel.

## Definition Of Done For Every Slice

- The change addresses a confirmed requirement or demonstrated failure.
- Obsolete code is removed rather than retained behind compatibility logic.
- Existing dependencies are checked before new code or packages are introduced.
- The current phase remains read-only and ends at validated workbook delivery;
  no slice adds partial mutation or post-execution behaviour.
- Changed scripts are executed against meaningful fixtures.
- Skill validation, identity, lint, unit tests, coverage, self-test,
  vendor-registry, release, and whitespace checks pass.
- A substantial behavioural change also passes an independent no-cheat forward
  test.
- A delivery change preserves every canonical record and passes exact row
  coverage, semantic fidelity, workbook-only readability, rendered-layout,
  privacy, and formula-injection checks.
- After step 5, every semantic slice passes through the complete isolated target
  path and produces a validated workbook before the next slice begins.
- The capability migration ledger is updated for every retained, strengthened,
  consolidated, deferred, or removed behaviour affected by the slice.
- The skill ends with one coherent current architecture, not old and new paths
  running in parallel.

## Next Evolution Slices

Keep the next work as two independent, working vertical slices:

1. Obtain one verified current GTM export fixture containing a Google tag, a
   Configuration Settings variable, an Event Settings variable, inherited
   settings, and an intentional inline override. Document its exact JSON
   representation without guessing template type codes or parameter paths. Build
   the end-to-end effective-settings fact model and correctness assertions before
   adding SEM-003 sharing candidates.
2. Obtain verified current export examples for explicit firing priority and one
   Didomi or OneTrust direct-browser blocked route. Build the effective event/blocker,
   priority, repeatability, CMP-state timing, product-capability, and consent-owner
   facts before generating any cleanup advice. Prove one redundant priority, one
   retained priority, one page/load firing-plus-blocker target, one later custom
   event target, one confirmed Advanced Consent Mode route, one direct
   non-Advanced Google route, one pure transporter, and one mixed route that must
   not receive the transporter exception.

Carry the first slice through the complete isolated target path and a validated
analyst workbook, then forward-test it before implementing the second. Do not
introduce a generic CMP abstraction until one vendor slice works end to end and
the second vendor proves the stable shared contract.
