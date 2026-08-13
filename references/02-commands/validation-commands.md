# Validation Commands

Run from the repository or installed skill root. Paths are examples.

## Contents

- Install and build the source-locked package
- Shard and validate the three reviews
- Compile, simulate, and build the cleanup plan
- Capture exact approval and compare completed audits
- Validate import JSON and create a separate change log
- Run project checks

## Install

```powershell
python -m pip install -e ".[analysis,dev]"
```

Verify that the runtime being used is the intended source tree:

```powershell
python -B scripts/gtm_skill_identity.py check --root . --pretty
python -B scripts/gtm_skill_identity.py identity --root . --pretty
python -B scripts/gtm_skill_identity.py verify C:\path\to\development-source C:\path\to\installed-skill --pretty
```

After the mandatory compact intake exchange, `check` is fail-closed before package creation. Regenerate the declared
manifest only as part of a deliberate validated skill build; never overwrite it
to hide an unexplained runtime difference.
A clean Git checkout may satisfy the same check from its exact tracked commit
and runtime file set. A dirty checkout or a non-Git installed/bundled tree still
requires a matching declared manifest.

## Build The Source-Locked Package

Run the intake preflight first:

```powershell
python -B scripts/gtm_context_model.py container.json --pretty
```

Present its provided, high-confidence inferred, and unresolved fields. Resolve
what is already known in a small context JSON. Unresolved business, naming,
ownership, lifecycle, folder, and preferred-target questions remain visible as
nonblocking owner decisions; continue all three reviews and block only the
affected mutation. Stop only for partial/ambiguous source identity, an unmodelled
entity layer, or missing proof that prevents an exact configuration judgment.

```powershell
python -B scripts/gtm_audit_package_build.py container.json --out-dir audit-package --pretty
```

With analyst-provided context:

```powershell
python -B scripts/gtm_audit_package_build.py container.json --context audit-context.json --out-dir audit-package --pretty
```

Add an explicitly approved tracking plan only when the analyst has identified it
as a requirement source:

```powershell
python -B scripts/gtm_audit_package_build.py container.json --context audit-context.json --requirements approved-plan.xlsx --out-dir audit-package --pretty
```

The normalized `approved_requirements.json` preserves exact source rows and is
copied only into the configuration and architecture bundles. It is absent from
shared facts and the operational bundle. Exact identifier links are candidates
for review, not inferred semantic replacements.

This creates:

- `source_model.json`
- `context.json`
- `shared_facts.json`
- `operational_scan.json`
- `operational_review.json`
- `technical_code_findings.json`
- `configuration_review.json`
- `architecture_review.json`
- `audit_package_manifest.json`
- `review-bundles/operational_sanitation/`
- `review-bundles/configuration_correctness/`
- `review-bundles/business_architecture/`

When a review is automatically sharded, its shard directory exists only inside
the matching `review-bundles/<run>/` directory. Temporary root staging
directories are removed after bundle construction. Use the matching
`review-scratch/<run>/` directory for notes, temporary extracts, and drafts;
sealing relocates an accidental undeclared bundle artifact there without
deleting it and records the recovery in the review seal.

The builder validates source identity before semantic work. An incomplete or
ambiguous artifact produces only `source_model.json` and a blocked manifest;
the absence of review scaffolds is intentional. Supply a complete, unedited
ContainerVersion export rather than treating the blocked result as a reduced
audit mode.

Assign each complete `review-bundles/<run>/` directory to a distinct fresh
reasoning context. The root orchestrator must not author a review. Complete the
review JSON only inside that directory and do not alter generated source
fields. Each scaffold includes its immutable `input_contract` and a pending
`completion_attestation`. Record the artifact roles actually used; do not load
anything outside the bundle except current official documentation explicitly
permitted by the contract. The bundle deliberately omits validator-only field
grading terms.

## Complete Automatically Sharded Reviews

Read `audit_package_manifest.json > review_work_units`. The package builder
automatically creates source-locked shards when a run has more than 40 primary
items or Run 2 has more than 120 authored behavior work units. A
`single_file` run is completed directly in its canonical review file. For a
`sharded` run, complete every file declared by that run's
`shard_manifest.json`.

Check each completed shard using its exact manifest filename, then merge the
complete run back to its canonical package path:

```powershell
python -B scripts/gtm_review_shards.py check audit-package/review-bundles/configuration_correctness/configuration_review.json audit-package/review-bundles/configuration_correctness/configuration-shards configuration_review.rows.0001.json
python -B scripts/gtm_review_shards.py merge audit-package/review-bundles/configuration_correctness/configuration_review.json audit-package/review-bundles/configuration_correctness/configuration-shards audit-package/review-bundles/configuration_correctness/configuration_review.json
```

The merge fails on missing, duplicated, pending, wrong-kind, or wrong-source
items. Shards from separate runs must remain separate. Current Run-2 shards are
source-hashed completion overlays: inspect the complete adjacent base review,
edit only the declared completion fields, and let merge reconstruct each full
row. The base preserves the exact generated branch, trace, contract,
technical-finding, D3-cross-check, and custom-code-line set. New packages create
no per-obligation micro-shards; legacy schema remains supported for resumability.
Merge persists one content-hash receipt per declared shard, rechecks every shard
after assembly, and records the resume contract. On failure, repair only the
named shard and rerun its check before resuming.

Use manual splitting only for a legacy package or to lower the limits for an
unusually dense object:

```powershell
python -B scripts/gtm_review_shards.py split audit-package/review-bundles/configuration_correctness/configuration_review.json audit-package/review-bundles/configuration_correctness/configuration-shards --max-items 30
```

Architecture splitting also creates `*.open_discovery.0001.json`. Complete its
analyst-added `DISC-*` comparisons and `open_discovery_attestation`; merge will
not mark the architecture run complete while that file is pending.

Run `check` immediately after completing each shard, using its exact manifest
filename. It verifies source locks, declared IDs, original obligation content,
and exact completion coverage; custom-code lines must also remain in source
order. It is an early corruption check, not a replacement for the complete run
validator after merge.

## Validate And Seal The Three Independent Runs

```powershell
python -B scripts/gtm_operational_review.py validate container.json audit-package/review-bundles/operational_sanitation/operational_review.json
python -B scripts/gtm_configuration_review.py validate container.json audit-package/review-bundles/configuration_correctness/configuration_review.json
python -B scripts/gtm_architecture_review.py validate container.json audit-package/review-bundles/business_architecture/architecture_review.json
```

Any failure means the run is incomplete. After each validator passes, the root
orchestrator supplies the exact identity of the fresh context that authored
that bundle. Sealing revalidates the bundle-local review, promotes it to the
canonical package path, and records immutable bundle/review hashes:

```powershell
python -B scripts/gtm_review_isolation.py seal container.json audit-package operational_sanitation --context-id "<actual-run-1-context-id>" --pretty
python -B scripts/gtm_review_isolation.py seal container.json audit-package configuration_correctness --context-id "<actual-run-2-context-id>" --pretty
python -B scripts/gtm_review_isolation.py seal container.json audit-package business_architecture --context-id "<actual-run-3-context-id>" --pretty
```

If a sealed run needs a validator-driven semantic correction, complete only that
run in a fresh reviewer context and preserve the prior artifact:

```powershell
python -B scripts/gtm_review_isolation.py seal container.json audit-package configuration_correctness --context-id "<fresh-amendment-context-id>" --amendment-of "<current-seal-sha256>" --pretty
```

Never reuse the original context ID or overwrite a seal without its exact parent hash.

The three context IDs must be real, distinct, and identical to their completed
review attestations. A review edited after sealing, a changed immutable bundle
input, or a review supplied from outside its bundle fails the completion gate.

## Compile And Simulate The Plan

```powershell
python -B scripts/gtm_operation_compile.py container.json audit-package/operational_review.json audit-package/configuration_review.json audit-package/architecture_review.json reconciled_operations.json --route "Pending user selection" --pretty
python -B scripts/gtm_future_state_check.py container.json reconciled_operations.json --output future_state_gate.json --pretty
python -B scripts/gtm_three_run_gate.py container.json audit-package --operations reconciled_operations.json --output completion_gate.json --pretty
```

Full completion always requires the audit and cleanup plan together. Omitting
`--operations` deliberately fails the completion gate, even when no mutation is
ultimately justified.

Generate the row-level approval template after delivering the plan. The analyst
must mark every row `Approve`, `Reject`, or `Amend`; do not delete rows or edit
hashes:

```powershell
python -B scripts/gtm_approval_response.py template reconciled_operations.json approval_response.json --pretty
python -B scripts/gtm_approval_response.py validate reconciled_operations.json approval_response.json --output approval_gate.json --pretty
```

Immediately before any approved direct mutation or before applying an import
artifact to GTM, run the exact execution preflight:

```powershell
python -B scripts/gtm_execution_guard.py reconciled_operations.json audit-package/context.json future_state_gate.json --source-export container.json --live-readback fresh-workspace-readback.json --approval-response approval_response.json --output execution_preflight.json --pretty
```

The source export must be the exact audit input, and the live readback must be a
fresh complete pre-mutation workspace snapshot. The guard compares their full
modeled object graphs while ignoring transport-only workspace metadata, rejects
drift, and enforces every operation prerequisite. This is static GTM
configuration readback, not browser/runtime QA.

An import artifact may be generated offline from the locked source export and
the approved, passing simulation. Until a fresh target readback passes this
preflight and the artifact is actually applied, label it planned/unapplied; it
cannot support an executed change log. Re-read the target immediately before
the real import because artifact generation is not proof that the workspace
has remained unchanged.

The validated response replaces direct `--approve` flags. Server, activation,
and post-observation confirmations remain separate response fields and are
accepted only when their evidence has been reviewed. An amended or rejected row
requires a regenerated subset/future state before mutation.

## Build And Gate The Cleanup Workbook

```powershell
python -B scripts/gtm_human_rows.py reconciled_operations.json human_rows.json --pretty
python -B scripts/gtm_workbook_build.py audit-package reconciled_operations.json human_rows.json cleanup_plan.xlsx
python -B scripts/gtm_audit_gate_check.py cleanup_plan.xlsx --operations reconciled_operations.json --pretty
python -B scripts/gtm_privacy_scan.py cleanup_plan.xlsx
```

The privacy command scans visible and hidden tabs by default. Use
`--visible-only` only for an explicit diagnostic, never for the delivery gate.

Only after those canonical checks pass, build and gate the derived analyst
workbook:

```powershell
python -B scripts/gtm_workbook_readability.py audit-package reconciled_operations.json cleanup_plan.xlsx analyst_editorial.json --future-state future_state_gate.json --completion-gate completion_gate.json --editorial-template --pretty
python -B scripts/gtm_workbook_readability.py audit-package reconciled_operations.json cleanup_plan.xlsx cleanup_plan.analyst.xlsx --future-state future_state_gate.json --completion-gate completion_gate.json --editorial analyst_editorial.json --manifest cleanup_plan.analyst.manifest.json --pretty
python -B scripts/gtm_workbook_readability_gate.py audit-package reconciled_operations.json cleanup_plan.xlsx cleanup_plan.analyst.xlsx --future-state future_state_gate.json --completion-gate completion_gate.json --editorial analyst_editorial.json --manifest cleanup_plan.analyst.manifest.json --pretty
```

The first command creates a pending, evidence-bound queue. Before the next
command, use a semantic AI review to author every `editable` field in ordinary
web-analyst language, set `status` to `complete`, and set `authoring_method` to
`evidence_locked_ai_semantic_rewrite`. Do not copy the deterministic projection
when it contains paths, contract lists, trace labels, or validator prose. The
builder verifies that the source/operation hashes, row bindings, IDs, objects,
and directions remain unchanged.

Use `--language fr-FR` when French builder-owned labels are explicitly wanted.
An analyst-authored decision-topic map may be supplied to both commands with
`--decision-topics decision_topics.json`; it may group only records requiring
the same answer and must cover every owner-decision source ID exactly once.
Without it, the builder conservatively groups only identical normalized
questions/recommendations, or cross-lens records with the same problem type,
answer class, and exact object scope. It never semantically combines two
differently worded decisions from the same review lens. Supply an authored map
only when it creates genuinely useful shared-answer topics.

Do not run `gtm_audit_gate_check.py` against the derived workbook: its eight-tab
contract applies only to `cleanup_plan.xlsx`. Deliver
`cleanup_plan.analyst.xlsx` only when its own gate returns `pass`. Otherwise
discard the derived file, retain the unchanged `cleanup_plan.xlsx` as the
technical recovery record, mark analyst delivery incomplete, and repair the
editorial/presentation step without rerunning any audit stage.

The cleanup workbook is not a change log.

## Compare Two Completed Audits

Run two complete audits independently before comparing them. The delta command
requires complete manifests, three complete runs, and valid independent seals;
operation packets are validated when present:

```powershell
python -B scripts/gtm_audit_delta.py previous-audit-package current-audit-package --output audit_delta.json --pretty
```

Use `--previous-operations` or `--current-operations` only when the packet is
stored outside its package. The output compares source objects, findings,
operations, decisions, families, and counts. It never substitutes a changed-only
scan or carries an old verdict, confidence, or score into the new audit.

## Validate A Generated GTM JSON

First generate the complete future container from approved operations:

```powershell
python -B scripts/gtm_future_state_check.py container.json reconciled_operations.json --future-export optimized-container.json --output future_state_gate.json --pretty
```

```powershell
python -B scripts/gtm_validate_artifact.py optimized-container.json --original container.json --mode overwrite --pretty
```

Use the route matching the artifact: `direct-readback`, `same-container-view`,
`same-container-final`, `overwrite`, or `new-container`.

## Produce A Separate Change Log

After real execution or artifact generation:

```powershell
python -B scripts/gtm_diff_operations.py container.json post-cleanup.json --route "Direct GTM/MCP/API" --operations reconciled_operations.json --execution-mode executed --json field_changes.json --pretty
python -B scripts/gtm_change_log_build.py field_changes.json change_log.xlsx
```

Use `planned` execution mode for a planned preview. Never label it executed.
In `executed` mode the command exits nonzero unless the complete readback
matches the approved simulated future state and every observed field change
links exactly to an approved operation. The JSON becomes the authoritative final
execution record, records its configuration fingerprint, and the workbook
builder refuses any executed payload whose certification is not `pass`.

## Project Checks

```powershell
python -m ruff check --no-cache scripts tests
python -m vulture scripts tests --min-confidence 80
python -B -m unittest discover -s tests -v
python -B -m coverage run -m unittest discover -s tests
python -B -m coverage report --fail-under=72
python -B scripts/gtm_self_test.py --pretty
python -B scripts/gtm_vendor_registry.py --max-age-days 365
python -B scripts/check_release.py
git diff --check
```

The release check also rejects production scripts importing repository tests.
The runtime-bundle test builds a source-locked package from the clean bundle
without relying on the repository test tree.

For every semantic correction, add a fixture that reproduces the failure and a
paired assertion that nearby true positives and architecture candidates remain.
Compare representative messy-container object, obligation, and relationship
counts before release; unexplained growth or lost coverage is a release blocker.
