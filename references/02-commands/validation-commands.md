# Workflow And Validation Commands

## Contents

- Build the evidence package
- Complete and seal source audits
- Reconcile and synthesize
- Prove fixed point
- Build and seal delivery

Commands assume execution from the skill root with Python 3.11+ and the bundled
spreadsheet artifact runtime available. Use the runtime path returned by the
workspace dependency loader for both environment values below; do not substitute
an alternate Node.js or XLSX authoring library.

```powershell
$env:CODEX_NODE = '<bundled node executable returned by the dependency loader>'
$env:CODEX_ARTIFACT_NODE_MODULES = '<bundled node_modules returned by the dependency loader>'
```

## Build The Evidence Package

```powershell
python -B scripts/gtm_audit_package_build.py container.json --out-dir audit-package --pretty
```

Optional locked context and approved requirements:

```powershell
python -B scripts/gtm_audit_package_build.py container.json --out-dir audit-package --context context.json --requirements requirements.json --pretty
```

For a defect discovered after canonical sealing, create an approved repair brief:

```json
{
  "kind": "gtm_semantic_repair_brief",
  "schema_version": 1,
  "status": "approved",
  "canonical_record_sha256": "<exact predecessor record hash>",
  "repair_records": [
    {
      "repair_id": "REPAIR-MISSING-NEXT-STEP",
      "canonical_decision_id": "<exact canonical decision ID>",
      "fields": ["next_step"],
      "reason": "The sealed decision lacks the required evidence-bound next step for faithful delivery."
    }
  ]
}
```

Then start one new same-source successor package:

```powershell
python -B scripts/gtm_audit_package_build.py container.json --out-dir audit-package-successor --supersedes-canonical-record prior-audit-package/canonical-record.json --semantic-repair-brief semantic-repair-brief.json --pretty
```

The builder validates the predecessor record/manifest/seal, exact source hash,
repair decision IDs and fields, copies lineage evidence, and adds each repair as
post-checkpoint evidence on its exact owning obligation. The successor reruns the
complete workflow.

The output directory must be new or empty. Package creation verifies the runtime
identity, builds the scan and obligation ledger, runs independent raw-source
assurance, and creates separate allowlisted Audit A/B bundles. Before completing
either checkpoint, the execution host must scope that context to its own bundle
and issue the required isolation receipt; otherwise block.

## Complete And Seal Source Audits

Each audit must run in a distinct fresh reasoning context whose host-enforced
scope cannot access the peer bundle or prohibited downstream artifacts. Complete
its `source-checkpoint.json`, including the host receipt, then seal the checkpoint:

```powershell
python -B scripts/gtm_cleanroom_audit.py checkpoint audit-package audit-a
python -B scripts/gtm_cleanroom_audit.py checkpoint audit-package audit-b
```

After checkpoint release, complete every obligation in that audit's `audit.json`
and seal independently. When `work-units/work-unit-manifest.json` declares
`family_sharded`, complete and close every unit, then merge it before validation:

```powershell
python -B scripts/gtm_audit_work_units.py audit-package/audit-bundles/audit-a
python -B scripts/gtm_audit_work_units.py audit-package/audit-bundles/audit-b
```

For `single_file`, edit `audit.json` directly and do not run the merge command.
Then validate and seal:

```powershell
python -B scripts/gtm_cleanroom_audit.py validate audit-package audit-a
python -B scripts/gtm_cleanroom_audit.py seal audit-package audit-a
python -B scripts/gtm_cleanroom_audit.py validate audit-package audit-b
python -B scripts/gtm_cleanroom_audit.py seal audit-package audit-b
```

Before canonical sealing, an audit amendment uses a new context and binds
`--amendment-of` to the current audit seal hash. After canonical sealing, use the
successor-package command above. Never edit a sealed result in place or expose
the other audit.

For an amendment, set both `audit.amendment_parent_seal_sha256` and
`audit.host_isolation_receipt.amendment_parent_seal_sha256` to that current seal
hash. Supply a new context ID and a new enforced receipt bound to the unchanged
audit bundle, then validate and seal with the same parent hash:

```powershell
python -B scripts/gtm_cleanroom_audit.py validate audit-package audit-a --amendment-of <current-seal-hash>
python -B scripts/gtm_cleanroom_audit.py seal audit-package audit-a --amendment-of <current-seal-hash>
```

Context and receipt identities are single-use across the complete workflow, not
just within this stage. The initial checkpoint and seal of one source audit form
one continuous owner; every other audit, neutral, projection, editorial, fidelity,
or reader owner must use new IDs.

## Reconcile And Synthesize

```powershell
python -B scripts/gtm_reconciliation.py scaffold audit-package
```

Complete `reconciliation.json` and every required row in
`neutral-verification.json` using fresh neutral contexts. For every row, supply
an enforced host isolation receipt bound to its
`neutral_bundle_manifest_sha256`; the context and receipt must not reuse or
access source-audit, checkpoint, peer-neutral, projection-review, or prior-cycle
identities. Then:

```powershell
python -B scripts/gtm_reconciliation.py finalize audit-package
python -B scripts/gtm_target_synthesis.py audit-package
```

The synthesizer accepts no new semantic choice. It validates operation identity,
exact source values, dependencies, write conflicts, `do_not_touch`, and projected
application.

## Prove Fixed Point

```powershell
python -B scripts/gtm_fixed_point.py start audit-package
```

When a cycle awaits review, complete `review-a` and `review-b` in separate fresh
contexts, seal both, scaffold/finalize exact reconciliation, then advance:

```powershell
python -B scripts/gtm_projection_review.py seal-review audit-package 1 review-a
python -B scripts/gtm_projection_review.py seal-review audit-package 1 review-b
python -B scripts/gtm_projection_review.py scaffold-reconciliation audit-package 1
python -B scripts/gtm_projection_review.py finalize audit-package 1
python -B scripts/gtm_fixed_point.py advance audit-package
```

Repeat only for the cycle requested by state. Three cycles is the hard maximum.
A `non_convergent_target_state` is a blocking result, not permission to skip work.
After a pass:

```powershell
python -B scripts/gtm_canonical_record.py audit-package
```

## Build And Seal Delivery

Create the deterministic map and editorial artifact:

```powershell
python -B scripts/gtm_delivery_mapper.py create audit-package --language English
```

Complete only the declared prose fields in `delivery/editorial.json` using a fresh
editorial context, then:

```powershell
python -B scripts/gtm_delivery_mapper.py validate-editorial audit-package
python -B scripts/gtm_delivery_mapper.py seal-editorial audit-package
```

Build and verify the workbook with the workspace artifact runtime:

```powershell
& $env:CODEX_NODE scripts/gtm_workbook_build.mjs audit-package
& $env:CODEX_NODE scripts/gtm_workbook_verify.mjs audit-package
```

Scaffold host-scoped fidelity and workbook-only reader reviews, complete them in
separate fresh contexts with their declared inputs only, inspect every rendered
preview, then seal:

```powershell
python -B scripts/gtm_delivery_reviews.py scaffold audit-package
python -B scripts/gtm_delivery_reviews.py seal audit-package
```

Their context and receipt IDs must be fresh against the entire package, including
source-audit and neutral identities and any prior workbook build.

The final seal returns the one workbook path. If sealed semantic content is
missing or wrong, start the same-source successor package described above. If
wording/layout alone fails, create a fresh editorial amendment, rebuild, and
repeat the affected delivery checks.
