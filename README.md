# GTM Container Audit & Cleanup

A reusable Codex skill for static, container-only Google Tag Manager audit and
optimisation. Version 2 replaces the former three complementary reviews and
mutation-era tooling with one verified scan, two host-scoped complete semantic
audits, deterministic target closure, and one analyst workbook.

## North Star

Make an existing GTM container as clean, correct, simple, and maintainable as if
a senior web analyst configured it today from an empty container for the same
proven needs. Identify defects, materially non-optimal configuration, justified
design, owner decisions, and evidence limits from container-visible evidence;
then produce an exact safe target and one trustworthy human workbook.

## What It Audits

The 27-area contract covers source integrity, object identity, dependency and
lifecycle graphs, duplicates and overlap, tag/template configuration, triggers,
priority/sequencing, CMP and consent architecture, Advanced Consent Mode,
client-to-server transport, variables, effective Google Configuration/Event
Settings, destination/page-view ownership, GA4/ecommerce/vendor semantics,
transformations, identity and sensitive fields, custom code/templates, Zones and
portability, naming, static complexity, business architecture, exact operations,
and fixed-point cleanup.

Important architectural positions include:

- direct non-Advanced vendor tags use a consent-free positive trigger plus one
  reusable denial blocker;
- pure client-to-server transporters use firing triggers only and inherit one
  canonical consent value for server-side enforcement;
- explicit firing priority is retained only for a proven same-event start-order
  need; and
- Google Configuration Settings and Event Settings are used only where effective
  field ownership and all material distinctions support shared ownership.

See [audit-coverage.md](references/03-rules/audit-coverage.md) for the complete
contract.

## Workflow

```text
source lock
  -> canonical scan + independent raw-source assurance
  -> typed obligation ledger
  -> Audit A and Audit B in host-scoped contexts
  -> reconciliation + targeted neutral verification
  -> exact operations
  -> projected fixed point (maximum three cycles) + deterministic replay
  -> sealed canonical record
  -> evidence-locked editorial mapping
  -> one verified analyst workbook
```

Both audits cover every semantic obligation; their object-first and target-first
orders reduce correlated misses. The execution host must make the peer audit
inaccessible until both are sealed; bundle hashes and receipts validate that
contract without pretending JSON alone proves access control. A third full audit
is replaced by neutral verification of disagreements,
one-sided findings, and material-risk conclusions.

The workflow ends at workbook delivery. It does not mutate GTM, create/apply an
import, create a version, publish, certify runtime behaviour, generate a change
log, or treat workbook delivery as implementation approval.

See [workflow-and-assurance.md](references/03-rules/workflow-and-assurance.md) and
[workbook-delivery.md](references/03-rules/workbook-delivery.md).

## Input And Output

Required: one complete unambiguous GTM ContainerVersion JSON export or equivalent
read-only evidence. Optional locked context and analyst-approved requirements are
supported; the latter are withheld until each audit's source-only checkpoint.

Output: one audit package containing the canonical technical record and proofs,
plus one `.xlsx` workbook with:

- `01 Overview`
- `02 Recommendations`
- `03 Decisions Needed`
- `04 Full Audit`
- optional `05 Custom Code` when source-applicable

## Repository Layout

- `SKILL.md` — agent routing and mandatory workflow
- `references/01-skill/` — purpose, scope, inputs/outputs, and acceptance
- `references/02-commands/` — workflow commands and forward-test protocol
- `references/03-rules/` — audit, workflow, product, naming, and delivery rules
- `scripts/` — deterministic evidence, validation, projection, sealing, and XLSX
  tooling
- `tests/` — v2 behavioural and end-to-end regression suite
- `.skill-build-manifest.json` — deterministic runtime identity

## Development Validation

```powershell
python -B scripts/gtm_skill_identity.py write --root .
python -B -m unittest discover -s tests -v
python -B -m coverage run --branch -m unittest discover -s tests
python -B -m coverage report --fail-under=72
python -B -m ruff check --no-cache scripts tests
python -B scripts/gtm_vendor_registry.py --max-age-days 365
python -B scripts/gtm_self_test.py --artifact-node $env:CODEX_NODE --artifact-node-modules $env:CODEX_ARTIFACT_NODE_MODULES
python -B scripts/check_release.py
git diff --check
python -B scripts/build_skill_package.py <new-empty-output-directory>
```

Set `CODEX_NODE` and `CODEX_ARTIFACT_NODE_MODULES` to the exact paths returned by
the workspace dependency loader before release validation. CI deliberately runs
`gtm_self_test.py --code-only` because the bundled workbook runtime is
host-provided; only the release-complete local self-test may claim workbook
validation. If that runtime is unavailable, workbook delivery blocks rather than
falling back to a second authoring implementation.

Licensed under the MIT License.
