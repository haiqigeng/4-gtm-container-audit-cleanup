# Operational Sanitation Run

This run is mechanical, exhaustive, and independent. It creates review
obligations, not automatic deletions.

## Contents

- Integrity
- Lifecycle and usage
- Exact and structural duplication
- Trigger structure and lint
- Folders and naming
- Legacy and destination inventory
- Mandatory result

## Integrity

- valid GTM export shape and unique object IDs;
- wrapped or direct ContainerVersion identity, locked current entity layers,
  array/object shape, and no silently ignored future entity-like layer;
- variable references, including code and template fields;
- firing/blocking trigger IDs and trigger-group members;
- setup/teardown tag names;
- folder IDs and custom-template IDs;
- built-in and GTM system references distinguished from missing objects;
- Zones, Google tag configurations, clients, and transformations included when
  exported.

For each missing setup/teardown name, list ranked existing-tag candidates using
normalized name identity, compatible type, peer sequence usage, and proximity.
A unique peer-supported candidate creates an exact `tagName` repair. Clearing
the setup/teardown list is not a safe fallback. When the affected tag itself
is paused with no active export-visible consumers and is selected for complete
lifecycle deletion, that deletion takes precedence over repairing its stale
sequence field; never emit both actions for the same inactive target. If no
candidate is unique, retain the broken edge and ask one source-specific owner
question.

## Lifecycle And Usage

- active tags versus paused tags;
- every paused tag retained for rollback, migration, or decommission review;
- objects consumed only by paused tags;
- unused custom and enabled built-in variables, triggers, templates, and folders;
- active-root reachability through recursive variables, built-ins, trigger
  groups, setup/teardown tags, templates, and Zone boundary triggers; an orphan
  cycle remains unused;
- server-client and transformation status, filter scope, and exported reachability
  signals without labelling server roots "unused" merely because they have no
  browser-style consumer edge;
- tags with no firing trigger, excluding tags genuinely invoked through setup or
  teardown sequencing;
- scheduled, paused, rollback, and owner-exception status where exported;
- malformed/reversed schedules, unknown firing options, malformed or ambiguous
  sequence targets, sequence role conflicts, paused targets, and cycles;
- no deletion based only on age or lack of a visible firing trigger.

After every consolidation design, recompute consumers and unused objects.

## Exact And Structural Duplication

- duplicate names within each GTM layer;
- exact configurations after removing identity/export metadata;
- export/workspace URLs, notes, and folder placement excluded from behavioral
  duplicate signatures so UI metadata cannot hide equal logic;
- same tag payload with different routes;
- payload normalization excludes firing/blocking routes, setup/teardown,
  schedule, firing option, priority, pause, consent, monitoring, and related
  controls so those differences do not suppress the candidate;
- identical dataLayer paths;
- identical normalized custom code;
- duplicate custom templates, clients, and transformations;
- built-in wrapper variables;
- duplicate destination/event configurations recorded for architecture review.
- identical event/destination contracts with different visible consent-control
  shapes recorded for configuration and architecture review.

An exact signature proves sameness of exported configuration, not sameness of
business purpose. Architecture must confirm consolidation.

## Trigger Structure And Lint

- malformed, empty, one-member, duplicate-member, nested, and cyclic trigger
  groups;
- invalid regular expressions and universally permissive patterns;
- duplicate conditions inside one trigger;
- contradictory equals/not-equals logic;
- complex condition sets needing simplification review;
- blocking triggers whose exact event cannot occur only when every firing route
  has a provable exact event constraint; mixed/unknown routes are not inferred;
- exact, normalized, near-equivalent, and subset conditions supplied to the
  architecture candidate queue.

For one-member groups, name every consuming tag/group/Zone and the exact child.
When the child is another group or participates in a cycle, resolve that
dependency first; only an acyclic route may be remapped before deletion.
Malformed scalar members remain invalid edges, while collisions with valid
member values stay visible as likely authoring mistakes.

The one-member-group finding must survive reconciliation as its own decision
ledger entry. It is complete only when every consumer is remapped before the
group deletion.

## Folders And Naming

- empty, singleton, overloaded, and unfiled structures;
- invisible/control characters, non-breaking or other non-standard whitespace,
  non-canonical Unicode forms, confusable cross-script names, and invisible
  corruption inside `{{variable references}}`;
- dominant local naming order and meaningful acronyms;
- inconsistent object-type prefixes, case, separators, scope, country/product,
  consent-blocking roles, and duplicate proposed names;
- unique final names within each GTM layer.

Naming proposals remain provisional until behavior, canonical objects, and
business-specific prefixes are understood.
Canonicalize a Unicode-corrupted name only together with every name-based
reference. If normalization collides with another object or two names merely
look confusable, preserve the candidate for analyst review instead of guessing
identity.
When neither an approved policy nor a reliable dominant local convention
exists, present one visible naming-policy question together with the analyst's
recommended convention instead of declaring every object nonconforming to an
invented default. The final action-complete plan remains blocked until the
complete rename set can be generated after that decision and after
consolidation/remaps are settled.

## Legacy And Destination Inventory

- Universal Analytics tag types, property IDs, active UA parameters, corroborated
  event names, and old ecommerce paths; a media event such as `AddToCart` or an
  unrelated false-valued `enhancedEcommerce` field is not UA evidence alone;
- a `(UA)`/Universal Analytics name without native UA type, property ID, or old
  ecommerce behavior is a label-only candidate. Record its exact consumers,
  tag types, and destinations. If every consumer is current GA4 and removing
  the stale label yields a unique name, propose that exact metadata rename;
  mixed, unknown, or colliding consumers remain candidates, and name evidence
  never proves legacy behavior or migration;
- fixed product positions and old product-array assumptions;
- vendor, destination/account/pixel IDs, endpoints, and external script hosts;
- export/UI metadata URLs excluded from destination and vendor inference, and
  every matched vendor retained for mixed custom code;
- web-to-server transport endpoints and exported consent-forwarding variables
  identified without judging unseen server behavior or treating an absent
  client blocker as a defect by itself;
- fixed numbered-slot formulas and aggregate expressions inventoried for
  configuration review;
- distinct consent-purpose variables or routes sharing identical logic queued
  for configuration and architecture review.
- Zone child containers, boundary/type-restriction shapes, duplicate children,
  unbounded scope, and empty enabled allowlists;
- manual-consent setting shape and official `notSet`/`notNeeded`/`needed` enum
  semantics, with unknown values kept as findings rather than normalized away.
- blockers recorded as control candidates until trigger overlap proves that
  they can affect the tag; consent-looking names/events do not prove forwarding.
  When every firing route and the blocker expose exact disjoint custom-event
  sets, remove the ineffective edge. Delete that blocker trigger in the same
  operation only when the edge removal leaves no exported consumer.

## Mandatory Result

Each module records object count, zero/findings status, stable finding ID,
source objects, deterministic evidence, and one explicit disposition. A later
run may justify an exception but cannot remove the record.

A deterministic defect may hold an interim visible owner decision during
analysis, but the final action-complete plan must resolve it through a cleanup
operation or a documented owner exception already present in the source-locked
intake context. A locked `review_candidate` may instead be retained when the
completed review proves its intentional distinction with source-specific
evidence; a locked review candidate or true business choice may remain a
precise owner decision. The exception must identify the finding ID, signature,
or affected object and provide a specific reason; the review
rationale must preserve that reason. `not_applicable` and
`container_evidence_limit` are not valid ways to dismiss a nonzero sanitation
finding.
Unfiled objects never disappear during presentation or reconciliation. When a
locked folder policy or source-supported role mapping exists, emit exact
`parentFolderId` moves; otherwise retain one visible policy decision with the
analyst's recommended taxonomy and list it in `target_organization`.

Deleting a consumed object requires the accepted remap set or exact field
change that removes the reference to cover every surviving consumer. Several
remap/change records may jointly provide that coverage; consumers deleted in
the same accepted operation set do not require remapping.
Every remap stays within its supported GTM layer, targets an object that
survives the accepted operation set, and is rejected when the resulting
consumer graph introduces a cycle. Apply all accepted renames, creations, and
deletions as one name model and reject any newly duplicated final name within a
layer.
