# Workflow And Validation Commands

## Contents

- Build the evidence package
- Complete and seal source audits
- Repair exact owning records
- Reconcile and synthesize
- Validate the combined target
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

The output directory must be new or empty. Package creation verifies the runtime
identity, builds the deterministic scan and obligation ledger, and creates the
locked inputs for both audits. Run scan assurance first in a separate fresh agent
context. Run Audit A and Audit B in two other fresh agent contexts;
neither audit input may contain the peer's findings. If the AI environment cannot
create those contexts, block with a concise capability message.

## Complete And Seal Source Audits

The two complete audits run in parallel, each in a distinct fresh agent context
over its locked bundle.
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

In its own fresh context, each agent edits only its own plan. The scaffold locks
neutral `candidate_groups` from structural fields; those groups are not verdicts.
Author compact
`decision_profiles` that assign complete candidate-group IDs, and exact
`obligation_overrides` for every obligation in a candidate that must split.
Review every obligation. The applicator expands profiles and proves exact-once
coverage. Share one
decision only when the criteria assessment, target, preserved distinctions,
next step, and evidence meaning are genuinely identical. Put each actionable
operation in a one-obligation profile or override because its target is unique.
Every obligation ID must appear exactly once. Do not group obligations where the
evidence, target, preserved distinctions, or next action differs.
Each profile has exactly this nesting:

```json
{
  "profile_id": "unique-profile-id",
  "candidate_group_ids": ["candidate-001"],
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

Before sealing, include source-proven consequential cleanup and exact consumer
remaps in a coherent target. Lack of an authored operation is unfinished agent
work, not an owner decision. Separate independently actionable defects from
unrelated owner questions in the same object or family, using existing atomic
records and structured open discovery where needed. Do not guess defaults or
claim a runtime failure solely from a source-visible missing guard or global reset.

The scaffold's locked `authoring_contract` lists class-required fields. Missing
runtime evidence limits runtime claims; it does not replace a static verdict for
container-visible configuration. The plan has a closed schema: locked
`candidate_groups`, authored `decision_profiles`, exact `obligation_overrides`,
`open_discoveries`, and the two global review conclusions.
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

Before canonical sealing, an audit amendment uses a new fresh agent context and
binds `--amendment-of` to the current audit seal hash. For a package whose
downstream outputs must be invalidated, use the focused repair procedure below
and apply these amendment commands in its working copy. Never edit a sealed
result in place or expose the other audit to the amendment owner.

For an amendment, set `audit.amendment_parent_seal_sha256` to that current seal
hash. Supply new agent/context labels bound to the unchanged audit bundle, then
validate and seal with the same parent hash:

```powershell
python -B scripts/gtm_cleanroom_audit.py validate audit-package audit-a --amendment-of <current-seal-hash>
python -B scripts/gtm_cleanroom_audit.py seal audit-package audit-a --amendment-of <current-seal-hash>
```

The amendment records its locked input and output hashes. Audit A and Audit B
labels remain distinct.

## Repair Exact Owning Records

For user-authorized repair of exact decisions, create a new working copy:

```powershell
python -B scripts/gtm_audit_repair.py audit-package audit-package-repair --decision-id <exact-canonical-or-obligation-or-source-decision-ID> --reason '<concrete defect>'
```

Repeat `--decision-id` for additional authorized exact IDs. A source-decision ID
selects its audit owner; a canonical or obligation ID resolves the associated
owning records. The output path must not exist, must have an existing parent,
and must not overlap the predecessor. The helper validates retained evidence and
copies source locks, scan, assurance, ledger, checkpoints, both complete audits,
seals, and histories unchanged. Only generated reconciliation, operation,
target-validation, canonical, and delivery outputs are excluded from the copy.
The original package remains unchanged. Read the returned repair receipt for
the exact owning records, prior seals, and excluded paths.

In `audit-package-repair`, a fresh context for each affected audit owner amends
only the exact requested source records through the existing plan and source-
audit amendment commands above. Use the owning audit ID and its current seal
hash, preserve unaffected judgments and checkpoint provenance, and keep peer
findings out of the amendment context. The helper does not author these changes,
produce a new scan, or validate old judgments against changed scan evidence.
Do not repeat package creation, source scan/assurance, or checkpoint commands.

Then run the reconciliation and synthesis commands below against
`audit-package-repair`, followed by target validation, canonical sealing, and
the dependent workbook gates. One fresh reconciler may retain a predecessor
neutral conclusion only if the complete reconstructed comparison, including
both source decisions, and its neutral evidence exactly match the predecessor
scaffolds. An ID or hash match alone is insufficient. That reconciler owns
changed rows and fresh completion provenance; the helper transfers no verdicts
automatically. This is staged repair of affected work and its dependants, not a
new complete source-audit run.

## Reconcile And Synthesize

```powershell
python -B scripts/gtm_reconciliation.py scaffold audit-package
```

In one separate fresh reconciliation-agent context after both audits are sealed,
read `reconciliation-units/manifest.json`, then complete every exact unit filename
declared there. Do not enumerate or infer unit paths. Each unit contains its
bounded deterministic comparison rows and matching neutral-verification rows.
Edit only the neutral-verification rows. Non-neutral comparison decisions are
prefilled from the sealed audits, and finalisation projects each completed neutral
decision into its owning comparison so the same judgment is never authored twice.
Complete
`reconciliation-completion.json` with the fresh agent/context labels and status
`complete`. Every neutral row includes the complete locked
`allowed_evidence_citations` list; use only exact entries from that list. Then:
Follow each unit row's scaffolded contract for rationale prose. Evidence binding
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

## Validate The Combined Target

```powershell
python -B scripts/gtm_target_validation.py audit-package
```

This command reconstructs the combined packet from sealed reconciliation,
simulates it from the locked original, checks references, dependencies, writes,
protected objects and implemented consent/routing safeguards, and recomputes
projected facts and assurance. It writes exactly five target-validation artifacts:

- `target-validation/projected-container.json`
- `target-validation/canonical-scan.json`
- `target-validation/scan-assurance.json`
- `target-validation/validation-proof.json`
- `target-validation/validation-seal.json`

Successful outputs are immutable; the command refuses to overwrite an existing
target-validation directory. Graph checks reject newly introduced failures and
record unchanged source issues with their existing reconciled dispositions.

The module exposes `validate_target` and `target_validation_seal_errors` for
maintained callers. Seal validation reconstructs the saved result from its
locked predecessors and rejects self-rehashed substitutes. No semantic target
review, new recommendation, or convergence gate follows this command. A failure
must be traced to the affected work; it is not permission to drop a finding.
Diagnostics distinguish explicit operation owners from object-matched candidates.
When ownership is unresolved, inspect the failed dependency and relevant actions
before reopening exact records; do not reopen the complete packet.

After a pass:

```powershell
python -B scripts/gtm_canonical_record.py audit-package
```

Canonical sealing binds the verified result under `target_validation` and
independently reconstructs its exact closed record and manifest inventory from
those predecessors. Passing proves the implemented static checks, not runtime
behaviour or exhaustive optimality. Repeated development evaluations belong to
the separate forward-test protocol, outside a normal product execution.

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
missing or wrong, use the focused repair procedure above. If
wording/layout alone fails, create a fresh editorial amendment, rebuild, and
repeat the affected delivery checks.
