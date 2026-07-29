# Validation Commands

Run from the repository or installed skill root. Paths are examples.

## Contents

- Install and build the source-locked package
- Shard and validate the three reviews
- Compile, simulate, and build the cleanup plan
- Validate import JSON and create a separate change log
- Run project checks

## Install

```powershell
python -m pip install -e ".[analysis,dev]"
```

Verify that the runtime being used is the intended source tree:

```powershell
python -B scripts/gtm_skill_identity.py identity --root . --pretty
python -B scripts/gtm_skill_identity.py verify C:\path\to\development-source C:\path\to\installed-skill --pretty
```

## Build The Source-Locked Package

Run the intake preflight first:

```powershell
python -B scripts/gtm_context_model.py container.json --pretty
```

Present its provided, high-confidence inferred, and unresolved fields. Resolve
material questions in a small context JSON before semantic review; non-material
questions remain visible without adding a completion gate.

```powershell
python -B scripts/gtm_audit_package_build.py container.json --out-dir audit-package --pretty
```

With analyst-provided context:

```powershell
python -B scripts/gtm_audit_package_build.py container.json --context audit-context.json --out-dir audit-package --pretty
```

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
- `operational-shards/`, `configuration-shards/`, or
  `architecture-shards/` when the corresponding review is automatically
  sharded

The builder validates source identity before semantic work. An incomplete or
ambiguous artifact produces only `source_model.json` and a blocked manifest;
the absence of review scaffolds is intentional. Supply a complete, unedited
ContainerVersion export rather than treating the blocked result as a reduced
audit mode.

Complete the three review JSON files. Do not alter generated source fields.
Each scaffold includes its immutable `input_contract` and a pending
`completion_attestation`. Record the artifact roles actually used; do not load
another run's verdict or repository test completion helper.

## Complete Automatically Sharded Reviews

Read `audit_package_manifest.json > review_work_units`. The package builder
automatically creates source-locked shards when a run has more than 40 primary
items or one configuration obligation group has more than 30 items. A
`single_file` run is completed directly in its canonical review file. For a
`sharded` run, complete every file declared by that run's
`shard_manifest.json`.

Check each completed shard using its exact manifest filename, then merge the
complete run back to its canonical package path:

```powershell
python -B scripts/gtm_review_shards.py check audit-package/configuration_review.json audit-package/configuration-shards configuration_review.rows.0001.json
python -B scripts/gtm_review_shards.py merge audit-package/configuration_review.json audit-package/configuration-shards audit-package/configuration_review.json
```

The merge fails on missing, duplicated, pending, wrong-kind, or wrong-source
items. Shards from separate runs must remain separate. Configuration obligation
shards preserve the exact generated branch, trace, contract,
technical-finding, D3-cross-check, and custom-code-line set.

Use manual splitting only for a legacy package or to lower the limits for an
unusually dense object:

```powershell
python -B scripts/gtm_review_shards.py split audit-package/configuration_review.json audit-package/configuration-shards --max-items 40 --max-obligations 20
```

Architecture splitting also creates `*.open_discovery.0001.json`. Complete its
analyst-added `DISC-*` comparisons and `open_discovery_attestation`; merge will
not mark the architecture run complete while that file is pending.

Run `check` immediately after completing each shard, using its exact manifest
filename. It verifies source locks, declared IDs, original obligation content,
and exact completion coverage; custom-code lines must also remain in source
order. It is an early corruption check, not a replacement for the complete run
validator after merge.

## Validate The Three Independent Runs

```powershell
python -B scripts/gtm_operational_review.py validate container.json audit-package/operational_review.json
python -B scripts/gtm_configuration_review.py validate container.json audit-package/configuration_review.json
python -B scripts/gtm_architecture_review.py validate container.json audit-package/architecture_review.json
```

Any failure means the audit is incomplete.

## Compile And Simulate The Plan

```powershell
python -B scripts/gtm_operation_compile.py container.json audit-package/operational_review.json audit-package/configuration_review.json audit-package/architecture_review.json reconciled_operations.json --route "Pending user selection" --pretty
python -B scripts/gtm_future_state_check.py container.json reconciled_operations.json --output future_state_gate.json --pretty
python -B scripts/gtm_three_run_gate.py container.json audit-package --operations reconciled_operations.json --output completion_gate.json --pretty
```

Full completion always requires the audit and cleanup plan together. Omitting
`--operations` deliberately fails the completion gate, even when no mutation is
ultimately justified.

Immediately before any approved mutation or import generation, run the exact
execution preflight:

```powershell
python -B scripts/gtm_execution_guard.py reconciled_operations.json audit-package/context.json future_state_gate.json --approve OP-0001 --pretty
```

Add the operation-specific server, activation, or post-observation confirmation
flags only when their evidence has been reviewed.

## Build And Gate The Cleanup Workbook

```powershell
python -B scripts/gtm_human_rows.py reconciled_operations.json human_rows.json --pretty
python -B scripts/gtm_workbook_build.py audit-package reconciled_operations.json human_rows.json cleanup_plan.xlsx
python -B scripts/gtm_audit_gate_check.py cleanup_plan.xlsx --operations reconciled_operations.json --pretty
python -B scripts/gtm_privacy_scan.py cleanup_plan.xlsx
```

The privacy command scans visible and hidden tabs by default. Use
`--visible-only` only for an explicit diagnostic, never for the delivery gate.

The cleanup workbook is not a change log.

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
links exactly to an approved operation.

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
