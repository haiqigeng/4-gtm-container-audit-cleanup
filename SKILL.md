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

Collect or infer the complete source, container type, website/domain, business model, material measurement context, CMP and routing context, SPA status, canonical IDs, staging hosts, exact `do_not_touch` object keys, naming policy, and requested execution route when known. Do not ask for values already present in the export.

Persist supplied, inferred, confirmed-empty, and unresolved values in `context.json` with their evidence basis. Context may guide interpretation but cannot replace container evidence or turn an assumption into a finding.

Before semantic review:

1. run `scripts/gtm_skill_identity.py check`; stop before intake unless a matching release manifest or exact clean Git checkout proves the runnable tree;
2. compare development and installed trees with `scripts/gtm_skill_identity.py verify` when both exist;
3. run `scripts/gtm_context_model.py` and present supplied, high-confidence inferred, and unresolved fields separately;
4. ask only material generated questions and rebuild with confirmed context;
5. stop if the source is partial or its ContainerVersion identity is ambiguous.

Use the exact syntax in `references/02-commands/validation-commands.md`. The package command is:

```bash
python -B scripts/gtm_audit_package_build.py container.json --context audit-context.json --out-dir audit-package --pretty
```

Omit `--context` only when no analyst context is available and the preflight has no pending material question.

## Non-Negotiable Architecture

A full audit has three independent runs against the same source, context, and shared-fact hashes:

1. operational sanitation;
2. configuration correctness;
3. business architecture.

Build one deterministic, judgment-free fact layer for identity, leaves, references, consumers, terminal sources, trigger logic, code/formula facts, consent routes, and behavior signatures. Each run may read the export, locked context, shared facts, and its own scaffold. Its prohibited inputs include foreign verdicts, reconciled output, and test helpers.

Use the three physical allowlisted directories under `review-bundles/`. Assign each directory to a different fresh reasoning context; the root orchestrator must not author any of the three reviews. There is no same-context fallback for a certified full audit. Semantic decisions must be authored independently; scripts may scaffold, shard, merge, validate, and seal but may not bulk-fill judgments. Promote a run into the canonical package only through `gtm_review_isolation.py seal`, using the real distinct context identity. Reconciliation is blocked until all three sealed review hashes match the canonical reviews.

Reconcile only after every run passes its own validator.

## Automatic Work Sharding

Package creation automatically reuses `scripts/gtm_review_shards.py` when a run has more than 40 primary review items or one configuration obligation group has more than 30 items. It records each run's `single_file` or `sharded` strategy in `audit_package_manifest.json` under `review_work_units`.

For a sharded run:

- work only in that run's `review-bundles/<run>/` directory and complete every primary and obligation shard declared by its `shard_manifest.json`;
- keep operational, configuration, and architecture shards separate;
- check each completed shard immediately against the canonical base review;
- complete the dedicated architecture open-discovery shard and attestation;
- merge the complete run back to the bundle-local review file, validate it, then seal it into the canonical package;
- never treat sharding as reduced scope or as additional verdict runs.

Use manual `split` only for a legacy package or when a lower bound is needed for an unusually dense object. A missing, pending, duplicated, or source-mismatched shard leaves that run incomplete.

## Three Audit Runs

### Run 1: Operational Sanitation

Read `references/03-rules/operational-sanitation.md`. Complete every generated finding and source-counted zero row through its five required inner passes. Resolve source-proven structural defects into exact operations unless a valid source-locked exception applies. Keep genuine lifecycle, organisation, or ownership choices visible with a precise question and recommended target.

Do not delete or consolidate from a signature alone. Prove reachability, every surviving consumer remap, layer compatibility, cycle safety, and final name uniqueness. Run 3 must confirm business equivalence for active consolidation.

### Run 2: Configuration Correctness

Read `references/03-rules/configuration-correctness.md` and every applicable topic in `references/03-rules/domain-contracts.md`. Complete every semantic object, source-owned logic leaf, recursive reference trace, consumer/peer context, D3 cross-check, applicable official contract, technical finding, and executable custom-code line exactly once.

Explain literal configured behavior with allowed source anchors. A source-visible Issue requires a concrete defect and exact operation when the target state is known; a genuine unknown retains the precise evidence boundary, owner question where applicable, and analyst recommendation. Do not use generic summaries, inferred runtime behavior, or `Not applicable` as fallback.

Evidence acquisition is exhaustive for every object. Only folders, built-ins, simple constants, and simple Data Layer Variables that pass the deterministic low-risk test may use the generated `structured_simple` representation of the same seven semantic dimensions. All tags, triggers, code/templates, formulas/lookups/regex, consent/vendor/server routing, findings, ambiguity, owner decisions, unresolved dependencies, and heavily shared objects require `deep` review. A simple row that reveals any issue or uncertainty must be escalated to `deep`; unknown or borderline objects never receive the concise path. The reviewer scaffold does not expose validator-only field grading terms.

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

Every substantiated cleanup disposition becomes the simplest exact operation. Every confirmed measurement family receives an explicit retained, changed, owner-blocked, or evidence-limited target state with preserved behavior, consent, and routing. Container-only evidence limits remain static boundaries, not runtime tasks.

## Build The Human Cleanup Plan

Read `references/03-rules/workbook-architecture.md`, then build and gate the
canonical eight-tab workbook with the existing exact commands in
`references/02-commands/validation-commands.md`. Do not change that workflow,
tab contract, or gate.

Only after the canonical workbook and its all-sheet privacy scan pass, read
`references/03-rules/workbook-output-contract.md`. Run the readability builder
and its independent gate as the final output step. The derived workbook is a
copy with five analyst tabs at the front; it is never an input to a review,
validator, reconciliation, compiler, future-state simulation, or completion
gate.

The visible workbook is an analyst decision document, not a proof dump:

- show every operation and genuine owner decision with a concrete recommendation;
- state the literal GTM problem, why it behaves that way, exact change, preserved behavior/settings, priority, approval, static readback, and rollback;
- retain the canonical filterable general category, exact problem type, and `layer:ID - Name` object labels;
- summarize retained business families and target architecture as well as defects;
- keep exhaustive paths, hashes, traces, branches, contracts, and code-line proof in JSON/hidden proof;
- show only the blocked draft row when action completeness fails;
- keep the cleanup plan and post-execution change log separate.

Do not weaken or omit actions to make the workbook shorter. Consolidate presentation only where every atomic operation, object, approval choice, and verification remains explicit.

In the derived analyst workbook, preserve complete coverage with rows rather
than extra columns:

- include every decision-ledger record in `A2 Audit Register`;
- include every atomic operation with deterministic exact action direction in
  `A3 Actions`;
- include every owner-decision source record under exactly one topic in
  `A4 Decisions`; an unanswered owner question never blocks output generation;
- inventory every Custom HTML tag in `A5 Custom HTML`, including long or legacy
  code, potential source-qualified dataLayer replacements, proof limits, and
  conflicts where a candidate variable is also scheduled for deletion;
- retain all eight canonical tabs unchanged.

Use conservative automatic decision grouping only when there are at most 15
owner-decision source records. Above 15, author a complete meaningful topic map
whose records genuinely require the same answer. Do not
add a traceability tab or link into hidden sheets; use stable IDs, links among
visible analyst tabs, notes for complete long scopes, and A1 unhide/filter
instructions. If the derived build or gate fails, reject only that file,
deliver the already validated canonical workbook, and report the readability
failure separately. Never rerun or loosen an audit stage to make the
presentation pass.

## Approval And Optional Execution

After delivering the audit and plan, ask for:

1. all operation IDs or an explicit approved subset;
2. direct GTM/API/MCP cleanup or a validated import JSON.

Do not ask for an aggressiveness mode. A subset is staged incomplete cleanup and must be re-simulated. Apply naming standardisation during approved cleanup unless explicitly excluded.

Before mutation, read `references/03-rules/mutation-playbook.md` and:

- require a passing execution preflight, rollback source, and exact approval;
- use a new workspace and modify existing objects where safe;
- re-read the complete workspace immediately before mutation and stop on drift;
- enforce exact `do_not_touch`, server-coupling, activation-risk, and decommission confirmations;
- validate and read back every batch;
- stop on drift, missing references, consent uncertainty, unexpected recreation, or any unapproved change;
- never publish or create a version unless separately requested.

Certify execution only when the complete readback equals the approved simulation and every observed field change links to one approved operation. Produce the separate field-level change log only after execution or generated cleanup artifact creation.

End every stage with one concrete next step.

## Portability

The reasoning contract works with Codex, Claude Code, Gemini, and comparable agents. Python 3.11+ provides deterministic scaffolds and gates; `openpyxl` builds XLSX and optional `esprima` enriches JavaScript facts. Missing tooling blocks full execution when evidence locks, exact obligation coverage, reconciliation, or delivery gates cannot be reproduced. State the prerequisite and stop; never invent a reduced fallback mode.
