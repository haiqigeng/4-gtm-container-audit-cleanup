---
name: gtm-container-audit-cleanup
description: Perform heavy operational Google Tag Manager cleanup as a container-only expert web analyst. Start from a complete JSON export or equivalent read-only GTM evidence, exhaustively audit sanitation, recursive configuration and custom code, consent and routing, and business architecture; turn every substantiated finding into the simplest exact cleanup plan; and, when explicitly approved, execute through GTM/API/MCP or produce a validated import JSON and change log. Use for naming, consolidation, migration, repair, deletion, and target-state redesign. Do not use for GTM Preview, live browser/network/dataLayer/CMP/vendor QA, legal decisions, website implementation, unseen server containers, unapproved mutation, or publication.
---

# GTM Web Analyst Audit And Cleanup

Act as an experienced web analyst, not a mechanical duplicate finder. Use only complete container configuration and exported code as audit evidence.

## North Star

> Do the heavy operational work needed to leave an existing GTM container as clean, simple, well-organised and logically correct as its real measurement needs allow. Exhaustively identify every container-visible cleanup and optimisation opportunity, decide the exact safe disposition and target state for each, and, when authorised, execute and verify the approved changes without regressing necessary measurement, consent behaviour, routing or integrations.

The audit is the evidence foundation; the actionable cleanup plan and verified resulting container are the product. Keep machinery only when it improves discovery completeness, decision quality, execution safety, or regression prevention.

## Reference Routing

Read these before every full execution:

1. `references/01-skill/purpose.md`
2. `references/01-skill/inputs-outputs.md`
3. `references/01-skill/acceptance-criteria.md`
4. `references/03-rules/execution-contract.md`

Then load the detailed contract immediately before its stage:

| Stage | Required reference |
| --- | --- |
| Operational sanitation | `references/03-rules/operational-sanitation.md` |
| Configuration and custom code | `references/03-rules/configuration-correctness.md` |
| GA4, ecommerce, media, consent, and server routing | `references/03-rules/domain-contracts.md` |
| Business architecture | `references/03-rules/business-architecture.md` |
| Reconciliation and structured actions | `references/03-rules/operation-schema.md` |
| Priority and approval | `references/03-rules/severity-calibration.md` |
| Canonical workbook | `references/03-rules/workbook-architecture.md` |
| Post-gate analyst workbook | `references/03-rules/workbook-output-contract.md` |
| Naming and mutation | `references/03-rules/naming-standardization.md`, `references/03-rules/mutation-playbook.md` |
| Separate post-execution log | `references/03-rules/change-log-template.md` |
| Exact commands | `references/02-commands/validation-commands.md` |

These references are authoritative. Do not replace their exact obligations with a shorter subjective checklist.

## Operating Boundary

- Require a complete GTM JSON export or equivalent complete read-only configuration evidence.
- Audit configured container logic only. Do not run or prescribe GTM Preview, browser, network, dataLayer, CMP, vendor-platform, or other runtime checks.
- Do not infer an unseen server container, legal decision, or website behavior.
- Audit and recommendation depth are always complete. Approval changes execution, never audit scope.
- Never mutate, create a version, or publish without the exact user approval required for that action.
- Block on ambiguous source identity or an unmodelled entity layer. Keep broken references in an otherwise valid export as findings while scanning everything else.

## Intake And Evidence Lock

Every new task starts with one compact intake exchange before file discovery,
identity checks, or semantic work. Ask the analyst to identify or confirm the
exact complete container JSON/equivalent source and the requested outcome, then
wait for the answer. Even when a likely file is visible or mentioned in prior
conversation, do not silently select it. If the request already names both,
acknowledge them and ask only one missing material constraint or for explicit
confirmation that the named source is the one to audit. After that first answer,
infer safe missing context and continue autonomously; do not turn the intake into
a questionnaire. If the confirmed source cannot be found, ask for the export or
exact path instead of selecting another file.

Collect or infer the container type, website/domain, business model, material measurement context, CMP and routing context, SPA status, canonical IDs, staging hosts, exact `do_not_touch` object keys, naming policy, and requested execution route when known. Do not re-ask for values already present in the confirmed export.

Persist supplied, inferred, confirmed-empty, and unresolved values in `context.json` with their evidence basis. Context may guide interpretation but cannot replace container evidence or turn an assumption into a finding.

Before semantic review:

1. after the mandatory intake answer, run `scripts/gtm_skill_identity.py check`; stop before package creation unless a matching release manifest or exact clean Git checkout proves the runnable tree;
2. compare development and installed trees with `scripts/gtm_skill_identity.py verify` when both exist;
3. run `scripts/gtm_context_model.py` and present supplied, high-confidence inferred, and unresolved fields separately;
4. record material generated questions as nonblocking owner decisions and continue the
   complete audit; ask immediately only when the source is partial/ambiguous, an entity
   layer is unmodelled, or missing proof prevents an exact configuration judgment;
5. stop if the source is partial or its ContainerVersion identity is ambiguous.

Use the exact syntax in `references/02-commands/validation-commands.md`. The package command is:

```bash
python -B scripts/gtm_audit_package_build.py container.json --context audit-context.json --out-dir audit-package --pretty
```

Omit `--context` when no analyst context is available. Pending business, naming,
folder, lifecycle, or ownership questions do not stop the scans or workbook; they
remain in A3 and block only an affected mutation whose exact target depends on the answer.
Add `--requirements approved-plan.xlsx` only when the analyst explicitly identifies
that file as an approved tracking-plan requirement. It is normalized as separately
labelled external requirement evidence for Runs 2 and 3; it never enters the
container-only shared facts or Run 1, and exact source rows are preserved without
inventing semantic matches.

## Non-Negotiable Architecture

A full audit has three independent runs against the same source, context, and shared-fact hashes:

1. operational sanitation;
2. configuration correctness;
3. business architecture.

Build one deterministic, judgment-free fact layer for identity, leaves, references, consumers, terminal sources, trigger logic, code/formula facts, consent routes, and behavior signatures. Each run may read the export, locked context, shared facts, and its own scaffold. Its prohibited inputs include foreign verdicts, reconciled output, and test helpers.

Use the three physical allowlisted directories under `review-bundles/`. Assign each directory to a different fresh reasoning context; the root orchestrator must not author any of the three reviews. There is no same-context fallback for a certified full audit. Semantic decisions must be authored independently; scripts may scaffold, shard, merge, validate, and seal but may not bulk-fill judgments. Promote a run into the canonical package only through `gtm_review_isolation.py seal`, using the real distinct context identity. Reconciliation is blocked until all three sealed review hashes match the canonical reviews.

Reconcile only after every run passes its own validator.

## Automatic Work Sharding

Package creation automatically shards large runs under the thresholds and exact
resume contract in `execution-contract.md`. Sharding changes workload shape, never
scope, depth, or the number of independent verdict runs. Work only inside the run's
allowlisted bundle, inspect its complete base evidence, check each declared shard,
repair only the named failing shard, merge without loss, validate, and seal. Keep
drafts in `review-scratch/`; never create new per-obligation micro-shards for current
packages. Exact commands are in `validation-commands.md`.

## Three Audit Runs

### Run 1: Operational Sanitation

Read `references/03-rules/operational-sanitation.md`. Complete every generated finding and source-counted zero row through its five required inner passes. Resolve source-proven structural defects into exact operations unless a valid source-locked exception applies. Keep genuine lifecycle, organisation, or ownership choices visible with a precise question and recommended target.

Do not delete or consolidate from a signature alone. Prove reachability, every surviving consumer remap, layer compatibility, cycle safety, and final name uniqueness. Run 3 must confirm business equivalence for active consolidation.

### Run 2: Configuration Correctness

Read `configuration-correctness.md` and applicable `domain-contracts.md` topics.
Complete their exact object, branch, recursive dependency, consumer/peer, contract,
technical, code-line, and D3 obligations. Generated narration is evidence, not a
verdict. Author substantive object and behavior-group conclusions wherever the
contract escalates risk; a `Correct` verdict is valid only after every source-visible
signal has a source-specific closure. A proven defect gets the simplest exact operation
when the target is container-visible; a genuinely unknown target keeps one precise
owner/evidence boundary and recommendation.

Apply the complete custom-code health and replacement review defined there, including
dataLayer/native/template/site-side replacement, null/type/timing contracts, security,
readability, and maintainability. Never substitute cosmetic minification for a repair.

Use the bundled official vendor registry first. For an unknown integration, perform current official-source research, update and validate the registry, rebuild the scaffold, and only then certify the contract.

### Run 3: Business Architecture

Read `references/03-rules/business-architecture.md`. Review every source-derived family, member chain, deterministic relationship candidate, singleton, Zone/configuration root, and open-discovery method independently from Runs 1 and 2.

Decide necessity, overlap, conflict, intentional distinction, canonical object, and simplest target architecture from configured event, route, destination, payload, consent, sequence, dependency, market/product, and ownership evidence. Generated candidates are the minimum queue, not the discovery boundary. Every additional relationship is a source-bound `DISC-*` comparison.

An actionable relationship verdict must change a candidate member's behavior. Retention needs a positive source-visible distinction for every member; an opaque signature, name similarity, or consumer count is not sufficient.

## Validate, Reconcile, And Simulate

Follow `references/02-commands/validation-commands.md` in this order:

1. validate each completed bundle-local review and seal it into the canonical package;
2. validate the three sealed canonical reviews;
3. compile the three reviews into one contradiction-aware operation packet;
4. simulate every structured operation on a copy of the export;
5. run the three-run completion gate with the operation packet and all three seals.

Do not average or vote across runs. Merge only identical complete structured mutations and preserve every lens's rationale. Block contradictory mutations, unsafe deletions/remaps, behavior changes through preserved or unresolved architecture, incomplete decisions, broken references, newly generated findings, unexplained broad count changes, or missing measurement-family target states.

For every High/Critical challenge or cross-run conflict recheck, use a fresh context
with only the exact source coordinates, source facts, and a neutral question. Do not
disclose another lens's rationale or an expected outcome. Record the independent
recheck context and verdict before sealing the final operation.

Every substantiated cleanup disposition becomes the simplest exact operation. Every confirmed measurement family receives an explicit retained, changed, owner-blocked, or evidence-limited target state with preserved behavior, consent, and routing. Container-only evidence limits remain static boundaries, not runtime tasks.

When the analyst asks what changed between audits, run
`scripts/gtm_audit_delta.py` only after both packages independently complete
their full three scans, seals, reconciliation, and gates. Compare objective
objects, findings, operations, decisions, families, and counts; never use the
previous result as a changed-only shortcut or carry forward its verdicts,
confidence, or score.

## Build The Human Cleanup Plan

Build and gate the canonical workbook exactly as `workbook-architecture.md` defines.
After its privacy scan passes, generate the evidence-locked editorial queue, use a
semantic AI pass to rewrite every visible analyst row from its bound facts into
plain web-analyst language, then build and independently gate the derived analyst copy
under `workbook-output-contract.md`. This is a presentation-only pass: it may change
wording but never IDs, objects, dispositions, priorities, operations, approval state,
or evidence boundaries. The analyst tabs must expose every atomic action,
genuine owner topic, retained business family, and Custom HTML technical/replacement
decision in literal analyst language; keep exhaustive proof in the canonical/JSON
record. Group only answer-equivalent owner records without losing children. Never use
the derived workbook as audit input, weaken actions for brevity, or loosen an audit
gate to improve presentation. If only the derived file fails, keep the validated
canonical workbook as the technical recovery artifact, report analyst delivery as
incomplete, and repair only the editorial/build/gate step without rerunning a scan.

## Approval And Optional Execution

After delivering the audit and plan, ask for:

1. all operation IDs or an explicit approved subset;
2. direct GTM/API/MCP cleanup or a validated import JSON.

Do not ask for an aggressiveness mode. A subset is staged incomplete cleanup and must be re-simulated. Apply naming standardisation during approved cleanup unless explicitly excluded.

Generate a versioned row-level response with
`scripts/gtm_approval_response.py template`. The analyst must mark every
operation `Approve`, `Reject`, or `Amend`; packet and row hashes bind the response
to the exact operation surface, and server/activation/observation confirmations
remain separate. Validate the response and pass it to the execution guard with
`--approval-response`. A missing, foreign, duplicated, or changed row blocks
execution.

Before mutation, read `references/03-rules/mutation-playbook.md` and:

- require a passing execution preflight saved as `execution_preflight.json`,
  rollback source, and exact approval; never make a GTM/API/MCP mutation call
  unless that saved artifact is bound to the current readback and selected packet;
- execute the compiler's dependency order; separately approve any reconciliation
  closure object made unused by earlier operations;
- use a new workspace and modify existing objects where safe;
- re-read the complete workspace immediately before mutation, bind that readback
  through the execution guard, and stop on drift;
- enforce exact `do_not_touch`, server-coupling, activation-risk, and decommission confirmations;
- validate and read back every batch, recording each operation ID before its call;
- stop on drift, missing references, consent uncertainty, unexpected recreation, or any unapproved change;
- never publish or create a version unless separately requested.

Offline import generation may use the locked source and approved passing
simulation without opening GTM authentication. Treat that artifact as
planned/unapplied; a fresh identity-bound readback is mandatory immediately
before applying it, and only the final post-import readback can certify an
executed change log.

Certify execution only when the final complete readback equals the approved simulation and every observed field change links to one approved operation. Save the passing final certification artifact; API/MCP success responses or visible workspace changes are never completion evidence. Treat that readback as the sole authoritative execution result; an executed change-log workbook must be regenerated from its passing certification. Produce the separate field-level change log only after execution or generated cleanup artifact creation.

End every stage with one concrete next step.

## Portability

The reasoning contract works with Codex, Claude Code, Gemini, and comparable agents. Python 3.11+ provides deterministic scaffolds and gates; `openpyxl` builds XLSX and optional `esprima` enriches JavaScript facts. Missing tooling blocks full execution when evidence locks, exact obligation coverage, reconciliation, or delivery gates cannot be reproduced. State the prerequisite and stop; never invent a reduced fallback mode.
