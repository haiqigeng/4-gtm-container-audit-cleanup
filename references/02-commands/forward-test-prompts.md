# Forward-Test Protocol

## Contents

- No-cheat rule
- Required fixture families
- Quality metrics
- Release decision

## No-Cheat Rule

Use unseen representative exports. Auditors may not read expected findings,
legacy outputs, the other audit, reconciliation results, or seeded-answer metadata.
Evaluate quality before speed. Compare retained behaviour and outcomes, never old
schemas or filenames.

## Required Fixture Families

- source identity: wrappers, workspaces/versions, malformed layers, duplicate IDs,
  built-in aliases, missing references, and exact `do_not_touch`;
- lifecycle and graph: paused-only reachability, orphan cycles, trigger groups,
  setup/teardown, schedules, priorities including explicit zero, and same-event
  competitors;
- Google settings: `gtcs`/`gtes`, inherited/local effective values, justified
  overrides, repeated inline values, configuration/event field ownership, loader
  and page-view ownership;
- consent/routing: Didomi, OneTrust, direct blockers, positive-trigger consent,
  confirmed and unconfirmed Advanced Mode, pure transporter inheritance, mixed
  direct/server branches, inconsistent client-side handoffs, and the explicit
  downstream server-container evidence boundary;
- semantics: GA4 recommended/custom events, ecommerce arrays and money fields,
  Ads/Floodlight/vendor IDs, transformations, identity/PII, Zones/environments;
- custom code: line segmentation, parser unavailable/partial/failed states,
  duplicate code with different consumers, listeners/timers/storage/requests,
  opaque code, and valid native/template replacement candidates;
- architecture: exact duplicates, intentional near-neighbours, singletons,
  cross-market and cross-destination distinctions, open discovery beyond generated
  candidates, and greenfield ownership; and
- delivery: every decision class, long technical details in comments, localisation,
  formulas beginning with `= + - @`, privacy-like values, navigation, recovery rebuild,
  and deliberately ambiguous prose.

Seed both material defects and valid-but-non-optimal configurations. Also seed
configurations that look repetitive but must remain distinct. Every retained or
strengthened capability in `references/03-rules/capability-migration.md` requires
an observable assertion.

## Quality Metrics

Measure:

- complete object/chain/family/relationship/singleton/container obligation recall;
- seeded material finding and optimisation recall;
- false-positive rate against intentional variants and evidence limits;
- independent discovery overlap and unique valid findings from Audit A/B;
- correct neutral handling of conflicts, one-sided findings, and material risk;
- exact operation validity, dependency safety, target coherence, and fixed-point
  convergence/non-convergence blocking;
- canonical-field completeness and repair ownership;
- workbook row coverage, locked-field equality, claim fidelity, standalone reader
  comprehension, formula/privacy safety, and rendered layout; and
- only after quality passes: wall-clock time, work-unit cost, amendment rate,
  conflict rate, projection cycles, and workbook build time.

## Release Decision

Release only when v2 is equal or better for every retained capability, detects
the new optimisation and consent/routing classes, preserves all seeded intentional
distinctions, has no unsupported cleanup advice increase, blocks every isolation or
non-convergence adversary, and produces one trustworthy workbook. A deferred
utility passes only by being absent.
