# GTM Container Audit & Optimize

A reusable Codex skill for static Google Tag Manager web-container audit and
optimization. Version 2.1 replaces the former three complementary reviews and
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
source-to-destination value semantics, identity and sensitive fields, custom
code/templates, Zones and portability, naming, static complexity, business
architecture, exact operations, and fixed-point optimization.

Important architectural positions include:

- direct non-Advanced vendor tags use a consent-free positive trigger plus one
  reusable denial blocker;
- pure client-to-server transporters use firing triggers only and inherit one
  canonical consent value for explicitly approved downstream enforcement;
- explicit firing priority is retained only for a proven same-event start-order
  need;
- Google Configuration Settings and Event Settings are used only where effective
  field ownership and all material distinctions support shared ownership; and
- `gtagConfig` direct settings and same-destination differences are explicit
  audited surfaces, while variable-backed transport hosts are resolved only from
  route-owned chains and independently assured.

Client-to-server transport remains in scope because its route, field ownership,
and consent forwarding are configured in the web container. Server-container
exports and server-container Clients, Transformations, and templates are outside
the skill.

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
orders reduce correlated misses. Both may read the same version-locked skill
rules, while the execution host must make the peer audit and downstream judgments
inaccessible until both are sealed. Bundle hashes validate artifact identity and
receipts record the host action for traceability; neither proves access control.
A third full audit is replaced by neutral verification of disagreements,
one-sided findings, and material-risk conclusions.

One ownership-aware registry enforces context and host-receipt freshness across
the complete workflow, including source audits, neutrals, projection reviews,
editorial work, fidelity review, and workbook-only reader review.

Every authority transition is independently reconstructed from sealed
predecessors: reconciliation scaffolds, operation packet, projected replay,
canonical record, and delivery map cannot be replaced by a merely self-consistent
rehash. Every public workflow and workbook command also rejects redirects
anywhere in the complete package tree before package I/O. Manifest-carried paths
are separately required to be canonical contained relative paths, and release
packages are bound to the exact clean source commit and runtime inventory.

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
python -B -m coverage run --data-file="$env:TEMP\gtm-python-coverage.data" --branch -m unittest discover -s tests
python -B -m coverage json --data-file="$env:TEMP\gtm-python-coverage.data" --fail-under=0 -o "$env:TEMP\gtm-python-coverage.json"
python -B scripts/check_release.py --coverage-json "$env:TEMP\gtm-python-coverage.json" --coverage-profile release-complete
python -B -m ruff check --no-cache scripts tests
python -B scripts/gtm_vendor_registry.py --max-age-days 365
python -B scripts/gtm_vendor_registry.py --online --max-age-days 120
python -B scripts/gtm_self_test.py --artifact-node $env:CODEX_NODE --artifact-node-modules $env:CODEX_ARTIFACT_NODE_MODULES
python -B scripts/check_release.py
git diff --check
python -B scripts/build_skill_package.py <new-empty-output-directory>
```

Set `CODEX_NODE` and `CODEX_ARTIFACT_NODE_MODULES` to the exact paths returned by
the workspace dependency loader and run
`& $env:CODEX_NODE scripts/gtm_workbook_build.mjs --preflight` before package
creation. CI deliberately runs
`gtm_self_test.py --code-only` because the bundled workbook runtime is
host-provided; only the release-complete local self-test may claim workbook
validation. If that runtime is unavailable, workbook delivery blocks rather than
falling back to a second authoring implementation. The online registry command is
the explicit release gate: every declared official source must respond, and any
required-source failure returns nonzero with attempted/succeeded/failed counts.

Licensed under the MIT License.
