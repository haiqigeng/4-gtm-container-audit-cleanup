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

Before package creation, verify the exact workbook implementation that will be
used at delivery:

```powershell
& $env:CODEX_NODE scripts/gtm_workbook_build.mjs --preflight
```

If this fails, stop before semantic work. Do not use another Node.js runtime or
XLSX library.

## Build The Evidence Package

```powershell
python -B scripts/gtm_canonical_scan.py container.json --out canonical-scan.json
python -B scripts/gtm_scan_assurance.py container.json canonical-scan.json --vendor-registry references/03-rules/vendor-registry.toml --out scan-assurance.json --agent-id scan-assurance-agent --context-id scan-assurance-context
python -B scripts/gtm_audit_package_build.py container.json --out-dir audit-package --scan-assurance scan-assurance.json --pretty
```

When those exact paths are supplied, run the maintained assurance command
directly. Do not precede it with a shell path probe, search, directory listing,
or filename inference.

Run the assurance command in its own fresh agent context. The package builder
reconstructs the canonical scan and assurance result and accepts the supplied
artifact only when its provenance and complete content match exactly.

Optional locked context and approved requirements:

```powershell
python -B scripts/gtm_canonical_scan.py container.json --context context.json --requirements requirements.json --out canonical-scan.json
python -B scripts/gtm_scan_assurance.py container.json canonical-scan.json --vendor-registry references/03-rules/vendor-registry.toml --out scan-assurance.json --agent-id scan-assurance-agent --context-id scan-assurance-context
python -B scripts/gtm_audit_package_build.py container.json --out-dir audit-package --context context.json --requirements requirements.json --scan-assurance scan-assurance.json --pretty
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
python -B scripts/gtm_canonical_scan.py container.json --out successor-canonical-scan.json
python -B scripts/gtm_scan_assurance.py container.json successor-canonical-scan.json --vendor-registry references/03-rules/vendor-registry.toml --out successor-scan-assurance.json --agent-id successor-scan-assurance-agent --context-id successor-scan-assurance-context
python -B scripts/gtm_audit_package_build.py container.json --out-dir audit-package-successor --supersedes-canonical-record prior-audit-package/canonical-record.json --semantic-repair-brief semantic-repair-brief.json --scan-assurance successor-scan-assurance.json --pretty
```

The builder validates the predecessor record/manifest/seal, exact source hash,
repair decision IDs and fields, copies lineage evidence, and adds each repair as
post-checkpoint evidence on its exact owning obligation. The successor reruns the
complete workflow.

The output directory must be new or empty. Package creation verifies the runtime
identity, builds the deterministic scan and obligation ledger, and creates the
locked inputs for both audits. Run scan assurance first in a separate fresh agent
context. Run Audit A and Audit B in two other fresh agent contexts;
neither audit input may contain the peer's findings. If the AI environment cannot
create those contexts, block with a concise capability message.

## Complete And Seal Source Audits

Each audit must run in a distinct fresh agent context over its locked bundle.
Record its agent/context labels and locked input hash in its provenance, complete
its `source-checkpoint.json`, then seal the checkpoint:

`pending` means the fresh audit agent must author the scaffold from the locked
evidence; it is not a blocked outcome. Review the complete locked inventory,
copy its supplied `inventory_sha256` into `reviewed_inventory_sha256`, and
directly complete the provenance, source-only conclusion, and any discoveries.
Write optional checkpoint `open_discoveries` as concise non-blank strings, not
semantic decision objects.
Do not generate or execute an audit-local helper and do not inspect the peer
audit. Before checkpoint sealing, do not read `work-units`: that directory does
not yet exist. The checkpoint command creates it. After release, read each
work unit at
`audit-package/audit-bundles/<audit-id>/work-units/<filename>`, using the
manifest record's exact `filename` field. `audit-scratch/<audit-id>` contains
only `audit-plan.json`, never work units or evidence. Do not add
optional shell inspection pipelines or guess artifact filenames; the documented
validators are the gates.
Do not use `rg`, `grep`, repository search, or exploratory shell commands during
semantic audit execution. Read the exact assigned bundle files directly. The
locked `audit-contract.json`, checkpoint scaffold, work-unit manifest, and unit
scaffolds are the complete authoring schema.
If no filesystem read tool exists, an exact-path read such as PowerShell
`Get-Content -LiteralPath` is allowed. Do not enumerate directories or infer a
path from command output.

The pre-checkpoint manifest is exactly `bundle-manifest.json`, never
`input-manifest.json`; copy its `bundle_manifest_sha256` value into checkpoint
`input_manifest_sha256`. Common pre-checkpoint files are `audit-contract.json`,
`bundle-manifest.json`, `context.json`, `locked-source.json`,
`source-checkpoint.json`, and `vendor-registry.toml`. Audit A also has
`canonical-scan.json`, `scan-assurance.json`, and `source-obligations.json`.
Candidate-blind Audit B instead has `blind-inventory.json`.
For actionable decisions, write `operation_family` as a human-readable phrase of
at least two words, such as `Remove redundant priority`, never as an underscore
token such as `remove_priority`.

```powershell
python -B scripts/gtm_cleanroom_audit.py checkpoint audit-package audit-a
python -B scripts/gtm_cleanroom_audit.py checkpoint audit-package audit-b
```

After checkpoint release, scaffold each audit's isolated declarative plan:

```powershell
python -B scripts/gtm_audit_plan.py scaffold audit-package/audit-bundles/audit-a audit-package/audit-scratch/audit-a/audit-plan.json
python -B scripts/gtm_audit_plan.py scaffold audit-package/audit-bundles/audit-b audit-package/audit-scratch/audit-b/audit-plan.json
```

In its own fresh context, each agent edits only its own plan. Author compact
`decision_groups`; every group must enumerate exact obligation IDs. Share one
decision only when the criteria assessment, target, preserved distinctions,
next step, and evidence meaning are genuinely identical. Put each actionable
operation in a one-obligation group because its operation and target are unique.
Every obligation ID must appear exactly once. Do not group obligations where the
evidence, target, preserved distinctions, or next action differs.
Each group has exactly this nesting; decision fields never sit beside
`obligation_ids`:

```json
{
  "group_id": "unique-group-id",
  "obligation_ids": ["OBL-..."],
  "decision": {
    "decision_class": "justified_as_is",
    "criteria_assessment": "...",
    "priority": "None",
    "confidence": "High"
  }
}
```

Use only the case-sensitive priority and confidence values in
`authoring_contract`. Every actionable decision must include the complete
declared `operation_proposal`; all action-list fields are present, even when
empty. Its uppercase `operation_id` must match the exact pattern and example in
`authoring_contract`. Target state, preconditions, static verification, and
rollback are strings meeting the contract's minimum word counts; preconditions
is not a list. Action-row `json_path` values are object-relative (for example
`$.tagFiringPriority`), never full `$.containerVersion...` source coordinates.
Plan application runs the established operation simulator against the locked
source before any audit write. Leave plan `open_discoveries` as `[]` unless a genuinely new semantic
record satisfies the complete structured discovery contract. Do not copy the
checkpoint's concise string notes into the plan.
The scaffold's locked `authoring_contract` lists class-required fields. Missing
runtime evidence limits runtime claims; it does not replace a static verdict for
container-visible configuration. The plan has a closed schema:
`decision_groups`, `open_discoveries`, and the two global review conclusions.
The applicator preserves locked identity/evidence fields,
validates the full authored result before writing, and performs the declared
work-unit merge automatically:

```powershell
python -B scripts/gtm_audit_plan.py apply audit-package/audit-bundles/audit-a audit-package/audit-scratch/audit-a/audit-plan.json
python -B scripts/gtm_audit_plan.py apply audit-package/audit-bundles/audit-b audit-package/audit-scratch/audit-b/audit-plan.json
```

Then validate and seal independently:

```powershell
python -B scripts/gtm_cleanroom_audit.py validate audit-package audit-a
python -B scripts/gtm_cleanroom_audit.py seal audit-package audit-a
python -B scripts/gtm_cleanroom_audit.py validate audit-package audit-b
python -B scripts/gtm_cleanroom_audit.py seal audit-package audit-b
```

Each successful seal creates a sequence-addressed immutable snapshot beneath
`audit-seals/work-unit-snapshots/<audit-id>/`. The sealed-audit gate checks the
current audit and every archived predecessor against its own snapshot. Do not
edit, copy forward, link, redirect, or prune these snapshots. The validator
recomputes each unit's immutable contract and rejects symlinks, junctions, reparse
points, and any resolved path outside the sealed snapshot root. It also
deterministically re-merges all decisions and discoveries from the snapshot and
requires exact equality with the sealed audit and completion proof. Malformed,
duplicate, unknown, or non-object nested rows block. The audit-seal, history,
bundle, snapshot, and canonical-audit roots must remain direct regular package
children and cannot be redirected. The package root itself must not be a symlink,
junction, or reparse point. Every public Python and workbook command performs the
same non-traversing check over the complete package tree before package I/O.

Before canonical sealing, an audit amendment uses a new fresh agent context and binds
`--amendment-of` to the current audit seal hash. After canonical sealing, use the
successor-package command above. Never edit a sealed result in place or expose
the other audit.

For an amendment, set `audit.amendment_parent_seal_sha256` to that current seal
hash. Supply new agent/context labels bound to the unchanged audit bundle, then
validate and seal with the same parent hash:

```powershell
python -B scripts/gtm_cleanroom_audit.py validate audit-package audit-a --amendment-of <current-seal-hash>
python -B scripts/gtm_cleanroom_audit.py seal audit-package audit-a --amendment-of <current-seal-hash>
```

The amendment records its locked input and output hashes. Audit A and Audit B
labels remain distinct.

## Reconcile And Synthesize

```powershell
python -B scripts/gtm_reconciliation.py scaffold audit-package
```

Complete `reconciliation.json` and every required neutral disposition in one
separate fresh reconciliation-agent context after both audits are sealed. Record
that agent/context label and the exact hashes of its locked inputs and sealed
output. Every neutral row includes the complete locked
`allowed_evidence_citations` list; use only exact entries from that list. Then:
Follow each scaffold's `authoring_contract` for rationale prose. Evidence binding
comes from the locked citation allowlist; rationale validation does not require
magic words.

```powershell
python -B scripts/gtm_reconciliation.py finalize audit-package
python -B scripts/gtm_target_synthesis.py audit-package
```

Finalisation first reconstructs the reconciliation scaffold and neutral queue
from both sealed audits. The synthesizer then reconstructs the complete packet
from sealed reconciliation; neither command accepts a self-rehashed substitute.
The synthesizer accepts no new semantic choice. It validates operation identity,
exact source values, dependencies, write conflicts, `do_not_touch`, and projected
application.

## Prove Fixed Point

```powershell
python -B scripts/gtm_fixed_point.py start audit-package
```

When a cycle awaits review, complete `review-a` and `review-b` with two fresh
review agents over the same locked projected evidence. Do not give either agent
the peer findings. Each reviewer scaffolds and applies its isolated declarative
plan; use only locked obligation IDs and coordinates, and never create an ad hoc
reference resolver:

```powershell
python -B scripts/gtm_audit_plan.py scaffold-projection audit-package 1 review-a audit-package/projection-scratch/cycle-01/review-a/review-plan.json
python -B scripts/gtm_audit_plan.py scaffold-projection audit-package 1 review-b audit-package/projection-scratch/cycle-01/review-b/review-plan.json
python -B scripts/gtm_audit_plan.py apply-projection audit-package 1 review-a audit-package/projection-scratch/cycle-01/review-a/review-plan.json --agent-id <review-a-agent> --context-id <review-a-context>
python -B scripts/gtm_audit_plan.py apply-projection audit-package 1 review-b audit-package/projection-scratch/cycle-01/review-b/review-plan.json --agent-id <review-b-agent> --context-id <review-b-context>
```

Use the actual cycle number in both the command and zero-padded scratch path.
Seal both, reconcile them in a separate fresh context, then advance:

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

Fixed-point sealing independently replays the packet from the locked source and
rebuilds projected evidence, obligations, decisions, state/history, proof, and
seals. Canonical sealing independently reconstructs its exact closed record and
manifest inventory from those predecessors.

## Build And Seal Delivery

Create the deterministic map and editorial artifact:

```powershell
python -B scripts/gtm_delivery_mapper.py create audit-package --language English
```

The mapper reconstructs the canonical record and exact delivery map before it
writes. Rehashing a modified canonical record or delivery map does not authorise
delivery.

Complete only the declared prose fields in `delivery/editorial.json`, then:

```powershell
python -B scripts/gtm_delivery_mapper.py validate-editorial audit-package
python -B scripts/gtm_delivery_mapper.py seal-editorial audit-package
```

Build and verify the workbook with the workspace artifact runtime:

```powershell
& $env:CODEX_NODE scripts/gtm_workbook_build.mjs audit-package
& $env:CODEX_NODE scripts/gtm_workbook_verify.mjs audit-package
```

Scaffold fidelity and workbook-only reader reviews, complete them with separate
fresh agents using their declared locked inputs only, inspect every rendered
preview, then seal:

```powershell
python -B scripts/gtm_delivery_reviews.py scaffold audit-package
python -B scripts/gtm_delivery_reviews.py seal audit-package
```

Record distinct agent/context labels and exact locked input/output hashes for the
two delivery reviews. Neither review receives the other's findings.

The final seal returns the one workbook path. If sealed semantic content is
missing or wrong, start the same-source successor package described above. If
wording/layout alone fails, create a fresh editorial amendment, rebuild, and
repeat the affected delivery checks.
