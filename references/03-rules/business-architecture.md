# Business Architecture Run

This run asks whether complete object chains form the simplest useful
measurement architecture. It starts from source evidence and does not inherit
the other runs' conclusions.

## Contents

- Family construction
- Deterministic and open relationship discovery
- Family and comparison judgments
- Invisible defects and target architecture

## Family Construction

Create one family per configured event/business action when available. Otherwise
group by non-system execution route, then vendor/destination/type. Keep
singletons. Enrich families with source-derived scope tokens such as funnel
step, question, country, product range, consent state, or page/market condition.

For every family traverse recursively:

- member tags and active/paused state;
- firing and blocking triggers;
- trigger-group members;
- setup and teardown tags;
- custom templates;
- directly and indirectly referenced variables;
- destinations, endpoints, event names, and consent settings.

Create families for Zones, Google tag configurations, exported server clients,
and transformations as architecture roots even when they do not connect to an
outgoing tag through an explicit GTM reference. Zone chains include boundary
triggers; Google tag configurations retain destination, transport, parameter,
and consent inheritance evidence.
Preserve missing and ambiguous dependency edges in the chain evidence rather
than dropping them because no target object can be traversed.

Assess every object in the resulting chain, not only the root tags. State its
configured chain role, business contribution, distinguishing logic, necessity,
status, and source anchors. Configuration Run 2 cannot be copied as this Run 3
business judgment.

Every member statement and every family/comparison conclusion must name the
generated evidence terms for that object or chain. Generic necessity or
architecture prose that could be reused for another container is incomplete.

Grouping by a name token alone is prohibited.

## Relationship Candidate Queue

Review every generated candidate:

- exact configuration or duplicate name;
- same tag payload with different routes;
- same vendor, destination, and event;
- tags and Google tag configurations sharing configured destination values;
- Zones governing the same child-container public ID set;
- same vendor/event with destination variants;
- cross-vendor implementation of one business event;
- recognizable custom-code event calls normalized to a conservative business
  event family while retaining their raw vendor event names;
- same event/destination contract with different consent, sequence, schedule,
  blocker, or browser/server-route controls;
- browser/server families joining a routed Google tag configuration,
  same-destination Google event tag, and same-business-event direct media or
  browser tag, with explicit consent, terminal-source, payload, and
  deduplication comparisons;
- cyclic trigger-group dependencies;
- Custom HTML `dataLayer.push` event names that differ from their Custom Event
  listeners only by a high-confidence spelling/casing near miss; never
  auto-correct a merely similar business event;
- SPA History Change page-view tags alongside a Google tag whose
  `send_page_view` is not explicitly disabled; confirm property-side Enhanced
  Measurement and retain exactly one virtual page-view sender;
- shared firing trigger or related trigger scope;
- shared terminal variable source or shared inputs;
- identical custom code;
- behavior-bearing environment/container variants that become equivalent only
  after development, staging, production, local, or `GTM-*` literals are
  normalized; UI/export metadata is excluded;
- normalized equivalent, near-equivalent, subset, or shared-step trigger logic;
- canonical funnel/question scope such as `Q1`, `question 1`, and `step 1`.

Candidate generation must preserve source paths, hashes, active/paused state,
and each member's evidence anchors.

The generated queue is a deterministic minimum, not a closed list. After it is
reviewed, perform one open discovery pass across every source object using:

- semantic name and business-term variants;
- normalized trigger conditions and execution routes;
- environment/container portability variants in behavior-bearing values;
- terminal source, formula, and output-shape overlap;
- shared consumers, destination, vendor, or event intent;
- consent, sequencing, and browser/server-route conflicts;
- funnel, question, journey, market, country, and product scopes.

Add every newly plausible relationship as a `DISC-*` comparison with source
object keys and evidence anchors. Record a source-complete discovery attestation
for all six methods. A zero-new-candidate result requires a concrete method and
coverage rationale, not `none found`.

The scaffold locks, for each method, its deterministic comparison IDs,
candidate objects, all-object review scope, and source-scope hash. The completed
method review must reproduce those fields, mark every candidate and source
object reviewed, and name source-derived comparisons, objects, or scope facts in
its conclusion. Do not substitute a subjective checklist or self-attested
coverage.

For sharded execution, complete deterministic family/comparison shards and the
separate open-discovery shard. The latter owns analyst-added `DISC-*` rows and
the final attestation. Merge must preserve source, context, and shared-fact
locks and cannot mark the run complete while the discovery shard is pending.

## Required Family Judgment

For each family and candidate, assess each member separately and then compare:

- literal role and business action;
- route and timing;
- trigger scope and exclusions;
- terminal input sources and formulas;
- output type, payload, destination, and deduplication key;
- consent, blocking, sequence, and browser/server role;
- consumers and downstream reporting/bidding use;
- product, market, country, page, funnel, or owner distinction;
- active, paused, rollback, and migration status;
- necessity and target architecture.

Choose one verdict: Exact duplicate, Functional overlap, Consolidation
candidate, Intentional variant, Complementary, Conflict, Unrelated, Owner
decision needed, or Container evidence limit.

Exact duplicate, Functional overlap, Consolidation candidate, and Conflict
require cleanup operations. Intentional variant, Complementary, and Unrelated
require `keep` plus a source-visible distinction for every member. Owner
decision and Container evidence limit require matching dispositions, and an
owner decision requires one precise interrogative question plus the analyst's
concrete recommended action. `not_applicable` is not a valid escape from a
generated cross-object relationship.

Same-payload/different-route, shared-Zone-child, cyclic trigger-group, and
browser/server consent/deduplication candidates are unsafe retention classes:
generic `Keep` is invalid. They require a cleanup/conflict conclusion or a
precise owner decision. A deterministic relationship already visible in the
export cannot be classified wholly as `Container evidence limit`; conclude the
visible architecture and use that boundary only for a named unseen runtime or
external fact.

An actionable verdict must contain an operation that changes at least one
relationship member's behavior. An unrelated object change or metadata-only
rename does not resolve the candidate. A before/after no-op does not count, and
the claimed candidate object key must match the exact source-path prefix being
changed. Exact-duplicate and consolidation operations keep a canonical member
of that relationship and delete a non-canonical member of it. Prove
configuration/business equivalence before ranking a keeper; consumer volume is
never equivalence evidence. Once exact configuration equivalence is proven,
there is no distinct business behavior left to choose: create the exact
consolidation operation and use the normal operation-approval gate rather than
an owner question. Select one default canonical member from exported evidence.
Rank active over paused, then more
container-visible consumers, then a name without copy/duplicate/old/legacy/
backup/test/temp markers; use the stable object key only as the final
deterministic tie-breaker. State the ranking evidence and cover every surviving
consumer remap before deleting another member.
Retained variants require a positive source-visible event, route, destination,
payload, consent, sequence, or dependency distinction for each member. An
opaque behavior-signature hash, a higher consumer count, or the absence of a
proven common target cannot justify `Keep`.

Unsafe owner questions identify at least two actual candidate objects and put
their route, Zone/child/boundary scope, trigger-group cycle, or browser/server
consent/deduplication decision inside the interrogative clause; a keyword list
followed by a generic question is not a decision. For a
browser/server family, client-container evidence cannot positively prove unseen
runtime event-ID/transaction-ID deduplication or end-to-end server consent
parity. When those states are absent or incomplete, rationale/effect text states
them as unproven, missing, conflicting, or unresolved and rejects positive
`complete`, `proven`, `aligned`, `guaranteed`, `identical`, `synchronized`,
`verified`, `equivalent`, or `consistent` claims, even when an unrelated clause
also contains a negative word.

Every `DISC-*` row declares at least one mapped comparison type, one or more
locked discovery methods, and appears in exactly those methods'
`additional_discovery_ids`. The methods must be suitable for the declared or
inherited relationship class. If its members are a subset
or superset of a deterministic unsafe candidate, or it declares that unsafe
type itself, it inherits the class's verdict policy, mandatory discovery
methods, and negative caution states. Discovery adds coverage; it cannot bypass
generated relationship rules.

Distinguishing terms are configuration evidence, not arbitrary lexical tokens.
Raw/truncated code, empty-structure placeholders, generic states, malformed
values, and bare numeric IDs cannot justify retention; use semantic routes,
events, destinations, consent controls, dependencies, or business roles.

A zero-new-candidate attestation names every locked discovery method and at
least three source-specific facts. Generic completion language does not pass.

## Common Invisible Defects

- several triggers represent the same funnel question through different names
  or event paths;
- a shared trigger causes two tags to send the same conversion;
- standard and custom purchase events duplicate revenue;
- one loader is repeated across tags or custom code;
- analytics and advertising consent outputs use the same condition by mistake;
- two variables share a source but transform or type it inconsistently;
- market/product variants differ only because naming drift hides one canonical rule;
- browser and server paths both send the same event without a deduplication key;
- individually correct objects are no longer needed by any current measurement objective.

## Target Architecture

Define canonical tags, triggers, variables, templates, consent helpers, and
folders. Preserve meaningful variants. Consolidation operations must identify
the canonical object, every consumer remap, non-canonical deletions, QA, and
rollback. Architecture decisions must align with sanitation before compilation.
