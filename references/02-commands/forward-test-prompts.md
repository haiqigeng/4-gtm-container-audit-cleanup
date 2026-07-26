# Forward-Test Protocol

Forward tests evaluate the skill from raw artifacts, not from a description of
the expected defect. Use previously unseen or synthetic exports and review the
three artifacts separately before inspecting the final cleanup plan.

## Contents

- Source-integrity, operational, configuration, and architecture regressions
- Reconciliation and future-state adversaries
- Human review and the no-cheat rule

## Test Families

### Source-Integrity Regression

Include artifacts with a valid export envelope, a direct ContainerVersion root,
a plain Container resource masquerading as a version, malformed entity lists,
non-object list members, missing IDs, duplicate IDs, and an unknown top-level
entity list even when that list is empty.

Pass condition: every complete valid shape proceeds with its true JSON root;
every ambiguous or incomplete shape blocks all three semantic scans,
compilation, artifact validation, and change-log attribution. A blocked package
must not contain empty semantic scaffolds that could be mistaken for a clean
audit.

### Operational Regression

Include exports with:

- setup-only tags without firing triggers;
- active and paused duplicate tags;
- variables used only by paused tags;
- enabled built-ins used only by unreachable or cyclic objects;
- missing variable, trigger, folder, tag-sequence, and template references;
- malformed, duplicate, self-referential, paused-target, and cyclic setup or
  teardown sequences, plus invalid schedules and firing options;
- empty, one-member, duplicate-member, nested, and cyclic trigger groups;
- malformed trigger-group members and nested sequence values that must produce
  findings without crashing the scan;
- one-member nested/cyclic groups whose remediation must resolve the dependency
  before remapping, plus malformed scalar values that collide with valid IDs;
- invalid/always-true regex, contradictory conditions, and ineffective blockers;
- mixed trigger routes where only some routes are event-constrained, to ensure
  conservative blocker reasoning;
- Zones with missing/duplicate children, malformed or unbounded boundaries, and
  malformed type restrictions or allowlists;
- duplicate paths/code/templates and built-in wrappers;
- behavior-equivalent duplicates whose export metadata, notes, folders, or UI
  URLs differ;
- identical payloads whose consent, firing/blocking route, sequence, schedule,
  firing option, priority, or pause control differs;
- same event/destination contracts with different visible consent-control
  shapes, plus consumed-object deletion plans with partial remap coverage;
- mixed-vendor Custom HTML and metadata URLs that must not become destinations,
  plus consent-looking names/blockers that must not become proof of control;
- empty, singleton, overloaded, and unfiled folder layouts;
- mixed naming conventions and duplicate proposed names.

Pass condition: Run 1 catches each source defect or records a correct zero row
without relying on Runs 2 or 3.

### Configuration Regression

Include:

- wrong dataLayer paths and event-time availability;
- revenue or quantity formulas that are syntactically valid but logically wrong;
- arrays required by vendor tags but scalars supplied by variables;
- nested variables, cycles, missing values, null fallbacks, and type coercion;
- missing references that differ from one existing name only by NBSP or another
  compatibility-space, plus ambiguous/fuzzy neighboring names that must not be
  auto-selected;
- duplicate custom-variable names and custom/built-in name collisions, proving
  that every candidate is retained and the reference is marked ambiguous;
- GA4 standard events with wrong ecommerce dataLayer/item contracts;
- GA4 purchase/refund events with missing transaction IDs or incorrect purchase
  linkage;
- media events with wrong IDs, item shape, currency/value, or deduplication;
- consent outputs with duplicated conditions;
- server-bound transporter tags without client blockers in two variants: one
  with a complete recursively sourced consent parameter/settings contract and
  one with missing or partial forwarding;
- custom code with multiple branches, returns, network/storage/DOM effects,
  unsafe APIs, fixed product slots, and parse failures;
- safe inline/DOM/storage/listener patterns that must close as reviewed
  non-defects rather than owner questions, alongside deterministic
  `dataLayer.reset`, internal-object, HTTP, cookie-attribute, debugger,
  unguarded-listener, and async-CMP defects;
- `document.write` code/support-setting matches and both mismatch directions,
  proving that only mismatches create exact Boolean actions;
- bare GTM-variable returns, one dynamic loader with both element and URL
  evidence, DOM mutation without selector reads, and global writes;
- the optional JavaScript parser unavailable or returning errors, proving that
  the mandatory parser-coverage limit cannot be silently marked correct;
- long/minified code whose first preview segment omits later network behavior,
  plus fallback attestations that omit one exact segment hash or describe only
  the first segment while ignoring a later endpoint/DOM/network effect;
- metadata-only custom templates whose executable behavior must remain opaque;
- one custom object containing multiple recognized vendors plus an unmatched
  external host, proving that no secondary contract disappears behind a primary
  label;
- client/server routing fields that should not be judged like ordinary browser tags.
- Google tag configurations and Zones with nested variable and trigger
  dependencies.
- deliberate reviewer claims of Correct/Compliant/Not applicable against
  malformed Zones, missing platform fields, unsupported vendor events, dynamic
  contract values, and reserved/example documentation URLs;
- empty nested objects, cross-object trigger conditions, sequence target state,
  missing Zone boundary targets, and downstream consumer fields required by D3.
- mutually exclusive trigger conditions, scalar/empty trigger-group members,
  repeated malformed setup/teardown entries, and a generic D3 conclusion that
  does not name the exact generated obligation;
- duplicate object rows, branch paths, D3 keys, contract checks, technical
  findings, and recursive traces that would overwrite under naive dictionaries;
- same-destination tags whose Google-tag peer carries a server endpoint,
  missing type, or consent state, proving that peer facts remain visible without
  being treated as automatic inheritance;
- an unknown integration whose analyst-supplied `official` URL belongs to an
  unrelated domain and was never versioned in the vendor registry.

Pass condition: Run 2 states literal object behavior, covers every logic leaf and
code line, traces all references, checks official contracts, and produces
source-linked defects. Generic prose must fail validation.

### Architecture Regression

Include:

- funnel `question 1`, `Q1`, and `step 1` paths with different conditions;
- duplicate loaders with different names;
- exact configuration duplicates, which must produce canonical/remap/delete
  operations rather than owner choices between identical copies;
- same payload on different routes;
- standard and custom purchase events with revenue duplication risk;
- mixed-vendor purchase calls inside one Custom HTML tag;
- shared consent helpers used for different Consent Mode outputs;
- product/country variants that are meaningful and variants that are naming drift;
- browser/server duplicate event paths with and without event-ID deduplication;
- a server-routed Google tag configuration, same-destination Google event tag,
  and direct same-business-event media tag that must form one triad comparison;
- individually correct but business-obsolete tags;
- intentionally distinct same-vendor destinations.
- tags and Google tag configurations that share a destination with aligned and
  conflicting settings;
- Zones that manage the same child-container set with aligned and conflicting
  boundaries.
- cyclic trigger groups and unresolved Zone dependencies preserved in family
  evidence;
- same destination/event with different consent, sequence, schedule, blocker,
  or server-routing controls;
- attempted keep/owner/container-limit/zero-discovery validator bypasses using
  generic text or incoherent verdict/disposition pairs.
- attempted `Keep` for same-payload/different-route, shared-Zone-child,
  trigger-cycle, and browser/server consent/deduplication candidates, plus an
  attempt to hide a source-visible relationship wholly in an evidence limit.
- actionable unsafe verdicts whose only operation changes an unrelated object
  or only renames metadata;
- analyst-added unsafe `DISC-*` rows omitted from their declared method review
  or marked Keep to bypass the deterministic policy;
- generic unsafe owner questions and positive claims of complete/proven runtime
  event-ID deduplication or browser/server consent parity when the source state
  is absent or unproven.

Pass condition: Run 3 assesses every member and chain, distinguishes intentional
variants from real overlap, and defines an exact target architecture.

## Reconciliation Adversaries

Test that compilation fails when:

- sanitation says consolidate but architecture says intentional variant;
- two reviews reuse one operation key for different mutations;
- one operation deletes an object another operation changes;
- remaps omit consumers or target a deleted object;
- a high-risk operation lacks challenge evidence;
- one run is pending or uses a different source hash.
- a non-consolidation behavior change conflicts with an architecture `keep` or
  unresolved verdict;
- a creation introduces a behavioral route without architecture support.
- Run 1 and Run 3 emit the same complete object-set owner choice, or downstream
  configuration rows consume one upstream Unicode-reference repair; the final
  plan must retain all evidence but show the decision/action once.

Test that future-state validation fails when a planned change creates a missing
reference, duplicate ID, orphan, new folder/trigger/Zone issue, or unresolved
cleanup finding. Include Zone boundary trigger remaps and Google tag
configuration references.

Test that shard merge fails when one item or file is missing, duplicated,
pending, belongs to another run kind, or uses another source hash.

## Human Review

Ask a web analyst who did not inspect the source export to review the workbook.
They should be able to understand each problem, affected objects, impact, exact
action, priority, readiness, and QA. The workbook must not reveal client secrets,
repeat the same conclusion across columns, exceed eight tabs, exceed the
canonical seven Cleanup Plan columns or six columns elsewhere, or mix the
cleanup plan with a change log. Confirm that the general category and affected
object columns support useful filtering without replacing the exact problem
type.
Give the analyst at least one invisible-Unicode row without explanation from
the evaluator. They must be able to state what character is wrong, why GTM can
treat the reference as missing, the intended readable variable name, the exact
field change, and which surrounding settings remain unchanged. Reject visible
rows led by raw JSON paths, hashes, validator wording, or generic
“maintenance-risk” boilerplate.

## No-Cheat Rule

Do not include expected findings in the execution prompt. Keep fixture labels
neutral. Evaluate false positives as well as misses, and compare each run's raw
artifact before viewing reconciliation.
