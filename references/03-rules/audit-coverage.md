# Audit Coverage Contract

## Contents

- North Star and decision model
- Consent and routing architecture
- Areas 1–27
- Evidence and source policy

## North Star

Make an existing GTM container as clean, correct, simple, and maintainable as if
a senior web analyst had configured it today from an empty container for the same
proven needs. Using only container-visible evidence, identify what is wrong, what
can be improved, and what should stay, then turn every justified improvement into
an exact, safe target state and deliver it in one trustworthy analyst workbook.

Apply the contract at four linked levels: object, implementation chain, business
or vendor family, and complete container. A deterministic scan creates facts and
candidates. Two independent audits create judgments. A candidate is never a
verdict.

Every applicable semantic obligation in areas 2–26 receives exactly one decision.
Area 1 is owned by the evidence/assurance gate; area 27 is owned by target
synthesis, projection, replay, and fixed-point status:

- `defect`: wrong, contradictory, unsafe, broken, or obsolete configuration;
- `correct_but_materially_non_optimal`: materially simpler or lower-drift target with the
  required behaviour preserved;
- `justified_as_is`: a positive source-visible distinction proves why it stays;
- `owner_decision`: a real business, policy, lifecycle, or ownership choice;
- `container_evidence_limit`: a conclusion needs evidence outside the supplied
  container; or
- `not_applicable`: permitted only when the deterministic source count is zero.

Record an optimisation only when repetition or complexity is visible, a current
GTM mechanism supports the target, all material distinctions are preserved, the
benefit is concrete, exact operations are expressible, and no runtime result is
invented.

## Consent And Routing Architecture

Classify each consent-relevant route before judging triggers:

| Route | Positive trigger | Consent owner |
| --- | --- | --- |
| Consent infrastructure | Consent Initialization or documented CMP default/update event | The consent writer; never vendor-gated |
| Confirmed Advanced Consent Mode | Normal lifecycle or business event without a granted-state condition | Coherent defaults and updates plus intrinsic product behaviour |
| Pure client-to-server transporter | Normal lifecycle or business event without a granted-state condition | One canonical consent value forwarded to a route host whose downstream consent-gating ownership is explicitly approved in locked context |
| Other direct browser/vendor route | Consent-free CMP timing/lifecycle event for page-load tags, otherwise the real business event | One reusable vendor, purpose, or category denial blocker |

For direct non-Advanced routes the blocker is mandatory and must fail closed for
absent, unknown, or denied state. Consent must not also be encoded in the positive
trigger or Additional Consent Checks. A Built-In Consent Check is intrinsic
template metadata, not a substitute for the selected control owner.

Advanced Consent Mode requires a typed locked approval matching every exact
Google destination and direct-browser/client-to-server route scope, including
the exact route host where applicable and concrete approval evidence, plus
coherent visible defaults, updates, consent types, and default timing. Native
Google capability, an unscoped approval, or approval without source-visible
writers is insufficient. A pure
transporter must have no direct browser-vendor branch, must inherit one complete
shared consent value, and must have locked approved context naming every route
host as owned by downstream server consent gating. Without that ownership proof,
classify client-gate removal as `owner_decision` or `container_evidence_limit` and
emit no removal operation. Mixed direct/server routes are split and judged per
branch; an inseparable branch follows the direct-route rule. Always conclude only:
“Client transport and consent-forwarding contract aligned or not aligned;
downstream server-container enforcement is outside this audit.”

## Areas 1–27

### 1. Source Identity And Evidence Completeness

- Scan account/container/workspace or version identity, export time, container
  type, every supported entity layer, malformed shapes, duplicate IDs, and absent
  layers.
- Block ambiguous, partial, or unmodelled evidence. Never infer an omitted
  resource or unseen server container.

### 2. Object Inventory And Identity

- Scan every key, ID, exact and normalised name, type, status, folder, note,
  template version, and relevant metadata, including naming anomalies.
- Audit role, vendor, destination, purpose, route, and owner; distinguish unknown
  purpose from evidenced obsolescence.

### 3. Dependency And Reference Graph

- Recursively resolve variables, firing and blocking triggers, trigger groups,
  setup/teardown, folders, templates, Zones, settings, destinations, clients, and
  transformations; identify consumers, cycles, and missing references.
- Require exact consumer remaps before retirement and no unresolved target cycle.

### 4. Lifecycle, Reachability, And Usage

- Scan active, paused, unused, paused-only, sequence-only, unscheduled, scheduled,
  environment-limited, rollback, and suspicious remnants.
- Do not delete from age, pause, or disuse alone; prove need, owner, rollback value,
  and safe disposition, then recompute reachability.

### 5. Exact Duplicates And Functional Overlap

- Scan names, structural/behaviour signatures, code, source paths, payloads,
  routes, loaders, page views, consent writers, near-duplicate and subset triggers.
- Classify exact duplicate, overlap, conflict, intentional variant, migration pair,
  or insufficient evidence while preserving event, timing, payload, consent,
  route, destination, market, product, and ownership differences.

### 6. Tag And Template Configuration

- Scan tag/template identity, version, publisher, permissions, IDs, fields,
  parameters, missing requirements, deprecated settings, and multi-vendor effects.
- Resolve current official and installed-template contracts; prefer native GTM,
  then a reviewed maintained template, before custom code.

### 7. Trigger Event And Condition Topology

- Model firing triggers as OR, conditions inside a trigger as AND, and blockers as
  an eligibility intersection. Scan event names, filters, regexes, overlap,
  contradictions, groups, lifecycle, SPA/history, and sequence invocation.
- Read Custom Event identity from the paired `_event` condition operands and keep
  one independently assured trigger inventory; a generic `value` field must not
  make the configured event literal disappear.
- Prove occurrence and data availability; flag weak selectors, impossible logic,
  subsumed routes, and trigger groups that do not express a real lifecycle AND.

### 8. Firing Options, Priority, Scheduling, And Sequencing

- Scan explicit priority including `0`, same-trigger competitors, firing options,
  setup/teardown and failure settings, sequence-only direct routes, cycles, and
  schedules.
- Remove explicit `0`, priority without a co-eligible competitor, priority already
  owned by sequencing, and priority used as asynchronous completion. Keep nonzero
  priority only for an evidenced same-event start-order need.

### 9. CMP And Consent Infrastructure

- Identify CMP/version, documented events/variables/tokens, default/update
  writers, Consent Initialization, consent types, duplicate writers, unknown-state
  behaviour, positive-trigger consent, blockers, and Built-In/Additional checks.
- Prove defaults precede dependants, updates map correctly, and timing/readiness is
  separate from vendor eligibility.

### 10. Direct Client-Side Consent Architecture

- For every direct vendor tag, scan positive route, consent conditions, blockers,
  CMP source and token matching, Additional checks, repeats, firing option, and
  later-grant behaviour.
- Except confirmed Advanced Mode and pure transporters, require a consent-free
  positive trigger plus one reusable denial blocker with exact token boundaries
  and fail-closed unknown state.

### 11. Advanced Consent Mode

- Scan relevant Google destinations, defaults/updates, consent types, timing,
  Built-In metadata, blockers, Additional checks, and route.
- Classify as Advanced only with explicit approved context and coherent visible
  implementation; otherwise apply direct non-Advanced policy.

### 12. Client-To-Server Transporter Architecture

- Scan transport URL ownership/inheritance, direct bypasses, canonical consent
  source and forwarding field, inline copies, client gates, destinations, event
  IDs, and browser/server overlap.
- Follow route values through every candidate variable chain rooted in an
  explicit route field or Google settings-owner reference. Do not classify a URL
  reached only through an unrelated field as a transport route.
- For a pure route require normal firing only, one shared inherited consent value,
  no direct bypass, and explicit approved downstream consent-gating ownership for
  every route host. Report missing, multiple, inconsistent, partial, inline,
  blocked, mixed, or ownership-unconfirmed implementations. Never remove a client
  consent gate from ownership-unconfirmed evidence.
- Area 12 is applicable only to tags with an effective direct, settings-inherited,
  or destination-owner server route. Consent metadata, blockers, CMP events, or a
  missing consent status alone must not create transporter topology.

### 13. Client-Side Server Handoff And Evidence Boundary

- Reconcile every web-container transport host, destination, event identifier,
  consent-forwarding field, shared settings owner, direct-browser branch, and
  mixed-route branch at container level.
- Identify inconsistent or incomplete client-side handoffs and state exactly what
  remains unknowable downstream. Do not request, ingest, or inspect a
  server-container export in this version.

### 14. Variable Graph And Source Contracts

- Resolve terminal source, type, data-layer path, default/null behaviour,
  constants, every lookup/regex row, Custom JavaScript, duplicate terminal
  sources, and consumers.
- Prefer the simplest compatible mechanism and reject unsafe defaults, type/shape
  drift, needless one-consumer indirection, and unjustified abstraction.

### 15. Effective Google Configuration And Field Ownership

- Resolve every effective field across Google tag, `gtagConfig`, Configuration
  Settings, Event Settings, inherited settings, local event tags, and overrides;
  retain provenance, value, type, lifetime, consumers, destination, consent, and
  route.
- Treat each `gtagConfig` as a configuration surface, including direct
  non-identity parameters. Compare same-destination owners by exact visible value
  and provenance so repetition and conflicts become explicit neutral obligations.
- Treat a referenced settings-variable name with multiple candidate objects as
  ambiguous. Retain every candidate object, field, source coordinate, consent
  value, and route in the audit facts; never select one owner by export order.
- Put configuration-wide values with one configuration owner, genuinely shared
  event parameters in one Event Settings owner, and event-specific values locally.
  Remove repeated identical inline values and preserve justified overrides.

### 16. Destination, Loader, And Page-View Ownership

- Inventory destination IDs, loaders/config tags, `send_page_view`, manual/history
  views, linker settings, routes, and brand/market/product/environment scope.
- Establish one deliberate owner per destination and route while preserving
  intentional multi-destination or scoped variants.

### 17. GA4 Event And Parameter Correctness

- Classify recommended, automatic, enhanced-measurement, and custom events; scan
  spelling/case/reserved names, parameters, inheritance, counts/types, user
  properties, debug fields, destination, and page-view ownership.
- Prefer current recommended semantics when they fit; distinguish a definite
  container duplicate from a potential property-side duplicate.

### 18. Ecommerce

- Scan ecommerce events, `items`, item fields, transaction ID, value/currency,
  tax/shipping/coupon, scope, duplicate routes, fixed item slots, legacy syntax,
  and deduplication fields.
- Require complete arrays and correct monetary/quantity semantics without
  invented defaults; runtime uniqueness and finance reconciliation remain out of
  scope.
- Determine applicability only from raw behavior-bearing container objects and
  executable template code. Official event contracts describe how to audit a
  visible implementation; they do not prove that ecommerce exists.

### 19. Ads, Floodlight, And Other Vendor Tags

- Capture loaders and actions, IDs/labels, values/products, matching fields,
  deduplication keys, routes, templates, scripts, and deprecated fields.
- Compare with current official vendor/template contracts; research unknown
  integrations before a definitive verdict.

### 20. Transformations And Source-To-Destination Semantics

- Trace material values through variables, transformations, settings, overrides,
  payload fields, and destinations, including type/cardinality and null/empty/
  zero/false/array/object handling.
- Preserve meaning; do not flatten, coerce, select, or default without an evidenced
  contract. Fix the real source instead of retaining compensating transforms when
  possible.
- This area is applicable to any behavior-bearing tag, variable, settings owner,
  transformation, custom template, or executable-code segment; it does not become
  inapplicable merely because the export has no Transformation object.

### 21. First-Party Data, Identity, And Privacy-Sensitive Fields

- Inventory `user_id`, user properties, `user_data`, enhanced conversions,
  matching data, hashes, PII-like fields/URLs, DOM selectors, secrets, and debug
  exposure.
- Assign one owner per identity product/destination, prevent raw PII and double
  hashing, and report legal/policy questions as external decisions.
- Determine applicability from the same raw behavior-bearing boundary; vendor or
  registry guidance must not create a sensitive-data implementation by itself.

### 22. Custom Templates And Custom Code

- Scan template metadata/permissions/domains, parser coverage, every executable
  segment, Custom HTML/CJS, globals, requests, `dataLayer` resets, storage, DOM,
  listeners, timers, `eval`, secrets, clones, callbacks, and async paths.
- Explain all material behaviour and side effects. Replace only after exact value,
  type, timing, consent, route, and destination equivalence is proven. Opaque code
  is an evidence limit, never a clean verdict.

### 23. Zones, Environments, And Portability

- Enumerate Zone boundaries, child containers, restrictions, duplicated duties,
  permissions, environments, embedded IDs/hosts, and production defaults.
- Require least necessary scope and explicit routing; preserve meaningful
  environment/child separation and state unseen child containers as boundaries.
- Evaluate portability for every configured object. An export without Zones or
  `gtagConfig` still has environment, embedded-identity, and portability scope.

### 24. Naming, Folders, Notes, And Documentation

- Scan inconsistent, duplicate, ambiguous, malformed, corrupted, and placeholder
  names plus folder/note/owner gaps.
- Apply naming after canonicalisation, make type/vendor/purpose/event/destination/
  scope understandable, and avoid cosmetic-only operations.

### 25. Static Efficiency And Complexity

- Measure object and code volume, duplicate script or listener bodies, large tables,
  repeated parameters, high fan-out, deep dependency chains, and one-consumer
  abstractions.
- Reduce independently maintained definitions and failure surfaces without opaque
  coupling or runtime-performance claims.

### 26. Business Architecture And Greenfield Target State

- Group every object into source-derived families by need, event, vendor,
  destination, loader, consent owner, route, source, market, brand, and product;
  include singletons and open discovery.
- For each family decide what is wrong, materially non-optimal, justified, or
  blocked, then define what a senior analyst would build from empty for the same
  proven needs.

### 27. Exact Operations And Fixed-Point Cleanup

- Compile creates, additions, changes, named-field removals, remaps, renames,
  pauses, deletions, and dependencies; project the complete target and rescan
  references, reachability,
  consent, routing, naming, conflicts, and newly unused objects.
- Admit only reconciled operations with exact before/after state, static
  verification, rollback, and deterministic fixed-point closure.

## Evidence And Source Policy

Do not claim actual firing, data-layer values, browser requests, cookie/CMP UI
behaviour, vendor receipt, GA4 property configuration, runtime deduplication,
legal compliance, runtime performance, unseen server enforcement, or missing
measurement from container absence alone.

Resolve version-sensitive criteria in this order: official Google/GTM material;
installed template source/schema/permissions; official CMP/vendor material;
reputable third-party discovery; then clearly labelled analyst inference. Record
URL, access date, applicable version, and supported rule. Product documentation
establishes a contract; container evidence is still required to apply it.
