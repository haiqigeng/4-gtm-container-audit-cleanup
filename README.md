# GTM Web Analyst Audit & Cleanup

[![Latest release](https://img.shields.io/github/v/release/haiqigeng/gtm-container-audit-cleanup?sort=semver)](https://github.com/haiqigeng/gtm-container-audit-cleanup/releases/latest)
[![CI](https://github.com/haiqigeng/gtm-container-audit-cleanup/actions/workflows/ci.yml/badge.svg)](https://github.com/haiqigeng/gtm-container-audit-cleanup/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/haiqigeng/gtm-container-audit-cleanup/blob/main/LICENSE)

A container-only workflow for doing the heavy operational work of cleaning
Google Tag Manager as an expert web analyst. It audits every supported object,
turns every substantiated problem into a precise cleanup action, and can apply
the explicitly approved actions through GTM while preserving necessary
measurement, consent behaviour, and integrations.

## North Star

Do the heavy operational work needed to leave an existing GTM container as
clean, simple, well-organised and logically correct as its real measurement
needs allow. Exhaustively identify every container-visible cleanup and
optimisation opportunity, decide the exact safe disposition and target state
for each, and, when authorised, execute and verify the approved changes without
regressing necessary measurement, consent behaviour, routing or integrations.

The audit is the evidence foundation. The actionable cleanup plan—and the
verified resulting container when execution is approved—is the product.

It is designed for Codex, Claude Code, Gemini, and other file-capable agents.

## v1.13.0 Highlights

- Requires one compact intake exchange on every new task before the agent selects
  a container source, then resumes autonomous full-scope execution.
- Recognizes exported filtered `CONSENT_INIT` routes without replacing regional
  hostname scope with the global Consent Initialization trigger.
- Resolves GTM serialization aliases such as `{{_event}}` to the exported Event
  built-in so dependency cleanup cannot delete a still-used object.
- Makes unresolved business-architecture rows a hard veto for behavior changes
  across their members and dependency chain, including cleanup closure.
- Keeps the existing A1-A5 workbook structure while adding a source/operation-
  bound AI semantic editorial step and paste-alone readability gate for every
  visible row.
- Requires a saved identity-bound execution preflight before any mutation and a
  passing final complete-readback certification before executed status.

## v1.12.0 Highlights

- Binds pre-mutation and final-readback certification to a strong GTM
  container identity while accepting compatible extra identity metadata and
  ignoring workspace-only readback churn.
- Computes cleanup-created orphan closure from the simulated future graph, so
  indexed edits, trigger groups, Zones, templates, and newly created consumers
  are handled without adding another scan.
- Makes nullable `.includes()` guard review lexical-scope aware and requires
  source-visible CMP/template consent behavior instead of treating a generic
  `command=default` field as proof.
- Preserves the declared canonical target when equivalent operations reconcile,
  blocks competing canonical targets, and accepts only the exact registered
  GTM system-trigger IDs.
- Moves cleanup approval packets to schema 5 and requires v1.12.0's execution
  boundaries to enforce that dependency contract, while keeping the three
  independent scans and their coverage unchanged.

## v1.11.1 Highlights

- Closes cleanup-created orphan chains after the three independent scans,
  exposes every derived deletion for separate approval, and orders consumer
  changes before dependency deletion.
- Requires a fresh complete workspace readback to match the audited object
  graph and every selected operation prerequisite before mutation.
- Certifies execution and executed change logs only from the final complete
  readback that equals the approved simulation.
- Fixes system-trigger validation, safe nullable-value guard recognition, and
  reconciliation of equivalent deletions without weakening source-bound
  reference or architecture checks.
- Allows an exact ineffective-blocker repair to retire only a proven dependent
  orphan chain, with complete source-graph validation and future-state gating.
- Adds real-run wording regressions so analyst actions and owner decisions stay
  literal, readable, and operational instead of falling back to machine prose.

## v1.11.0 Highlights

- Adds source-bound detection for unbounded polling, unsafe `postMessage`,
  dynamic-cookie defects, nullable dataLayer variables, missing-value coercion,
  consent-initialisation timing, and semantic name/output mismatches, with safe
  neighbours that prevent pattern-only false positives.
- Generates stable architecture candidates for duplicate vendor loaders and
  competing consent-writer sequences even when no event parameter exists.
- Requires source-specific closure for material review signals and prevents a
  deterministic technical defect from being parked as an owner decision.
- Preserves the three independent scans while adding append-only fresh-context
  amendments and named-shard repair/resume instead of restarting valid work.
- Makes analyst consequences literal and problem-specific, and reduces
  `SKILL.md` from 295 to 211 lines by routing duplicated detail to authoritative
  contracts without reducing audit scope or evidence.

## Who It Helps

- Web analysts, analytics consultants, GTM specialists, and agencies.
- Marketing and media teams reviewing conversion-signal quality.
- Developers, dataLayer owners, and consent owners receiving cleanup work.
- Teams that need a reviewable plan before anyone changes a container.

## Questions It Answers

- What is broken, duplicated, unused, obsolete, or unnecessarily complex?
- Does each tag fire for the action its name and event claim to measure?
- Do triggers and recursive variables provide the expected values at that event?
- Do GA4, ecommerce, media, consent, and server-routing settings follow their
  official configuration contracts?
- Do calculated values such as revenue or quantity make business sense?
- Are apparently different funnel steps, vendor events, or consent routes doing
  the same job?
- What should remain, change, consolidate, or be decided by an owner?
- Can the approved target state be applied without breaking references?

## The Three Reviews

Every complete audit first builds one source-fact map: what objects exist, what
they reference, where values originate, how triggers compare, which formulas
are present, and how consent routes are configured. This prevents three agents
from extracting the same container three different ways.

The audit then runs three independent reviews against that same fact map and
the raw export. The map contains evidence, not conclusions, so one review still
cannot substitute its conclusions for another.

Each review is source-locked to its own physical allowlisted bundle and must be
authored in a distinct fresh reasoning context. Another run's verdict or a
repository test helper cannot complete a real audit run. A validator-passing
bundle is sealed before promotion to the canonical package; changed inputs,
reused context identities, or post-seal edits fail completion.

The package gate reconstructs this map and the audit context from source. A
copied or stale hash is not enough to pass.

1. **Operational sanitation** checks references, unused and paused-only
   objects, exact duplicates, trigger groups, regex and blocker defects,
   sequencing, schedules, folders, Zones, templates, built-ins, naming,
   Unicode/reference integrity, consent-control shape, and active-root lifecycle hygiene. Remediation for a
   nested/cyclic trigger group is dependency-ordered, never a blind flatten.
   Payload comparison deliberately excludes route, consent, sequencing,
   schedule, and firing controls so equal payloads on conflicting routes remain
   visible; deleting a consumed object requires complete remap or exact
   reference-removal coverage.
2. **Configuration correctness** reviews every tag, trigger, variable,
   Zone, template, client, Google tag configuration, and transformation. It
   follows every referenced variable to every possible terminal source, checks
   every source-owned configuration branch exactly once, keeps cross-object
   leaves as D3/contract context, inspects every exported executable custom-code
   line, and
   tests all matched and unknown-host vendor contracts. UI/export metadata is
   excluded from host inference, and recognized transport endpoints stay in the
   server-routing contract. Cross-object trigger/sequence conditions, empty
   structures, destination peers, and downstream consumer-event fields remain
   citeable D3 evidence, including peer server/type/consent state without
   assuming destination inheritance. Decisive malformed/missing/cyclic source
   states create locked Issue/Unclear obligations across branches, D3,
   contracts, defects, and the overall verdict; duplicate review identities
   fail rather than overwrite. GA4 purchase/refund reviews include
   explicit transaction-ID obligations. Opaque custom templates and incomplete
   parser coverage cannot be certified as Correct. Lookup/regex row/default/order
   defects, behavior-bearing portability literals, dataLayer resets, GTM
   internals, manual gtag senders, cookie set/update versus deletion scope,
   dynamic-cookie attributes/retention arithmetic, listener registration/readiness,
   bounded recursive polling, exact postMessage origin/payload validation,
   nullable DLV string use, missing-value coercion, semantic name/output alignment,
   interval/observer lifecycle, and full
   code-health/maintainability findings are explicit obligations. The same locked review covers `document.write`
   support, missing Custom HTML script wrappers, Optimize/anti-flicker
   remnants, callback-based CMP reads, and redacted credential candidates.
   Versioned official contracts lock supported/deprecated
   events, required fields, static value rules, and endpoints. Community-template terms,
   help, tests, licenses, permissions, and comments are not miscounted as
   executable lines; permissions remain contract evidence. Parser fallback describes
   every individual code segment, not merely its hashes, and cannot invert a
   source-proven send, request, DOM/script effect, dataLayer/storage action, or
   return while citing the right tokens. Source-proven health/security signals
   require a finding, concrete proposed action, evidence-bound exception basis,
   or source-specific closure; relabeling the verdict is not resolution.
   A confirmed technical issue links to exactly one concrete defect.
   Evidence collection remains exhaustive for every object. The source-locked
   ledger retains every leaf, recursive trace, code segment, contract topic,
   technical finding, and D3 check exactly once. Related evidence is presented
   as meaningful behavior groups, so the reviewer authors an object-level
   correctness basis and escalated conclusions instead of repeating seven
   near-identical paragraphs. Generated branch and trace narration is evidence
   rendering, not an automated correctness verdict; every complex, risky,
   ambiguous, uncertain, shared, or actionable object still requires substantive
   judgment. Every Custom HTML/CJS review selects an explicit keep/optimise/
   repair/shorten/refactor/consolidate/replace/remove/owner disposition. A code
   rewrite binds to the exact source hash/path, proves the concrete gain, names
   preserved behavior, and supplies a complete replacement body; formatting-only
   rewrites fail. Native GTM, maintained-template, dataLayer variable,
   consolidation, and site-side producer replacements are first-class candidates,
   never assumptions of equivalence.
3. **Business architecture** compares complete execution chains and business
   families. It finds functional overlap, conflicting funnel logic, duplicate
   destinations, Zones governing the same child container, unnecessary
   variants, trigger-group cycles, custom-code business events, route/consent
   variants, duplicate vendor loaders, multiple consent-writer sequences,
   behavior-equivalent environment/container variants, browser/server event-destination-consent families, unresolved
   chain edges, dataLayer push/listener spelling near misses, SPA History versus
   `send_page_view` conflicts, and missed consolidation that exact matching cannot reveal.
   Visible unsafe relationships cannot be retained or hidden behind a generic
   container-evidence limit without a candidate-bound operation or precise,
   relationship-specific owner decision. No-op and object/path-mismatched
   operations do not count. Missing runtime deduplication or consent-parity
   proof stays explicitly unproven and cannot be restated as guaranteed,
   identical, synchronized, verified, or equivalent.

The third review also performs an open discovery pass. This catches objects
that look different but serve the same funnel step, use the same terminal data,
send the same business event, or apply conflicting consent logic. Machine-made
candidate lists are the starting point, not the boundary of the audit.
Every added discovery declares a mapped comparison type, is attributed to
suitable locked methods, and inherits any deterministic unsafe-class policy
across candidate subsets/supersets or from its own declared unsafe type.
Retention must cite how every member actually differs; verdicts, dispositions,
owner questions, and zero-discovery attestations are validated as one coherent
decision rather than independent form fields.

Only after all three validators pass and their bundle-local outputs are sealed
are their actions reconciled and simulated
against a future copy of the container. The simulation reruns sanitation,
configuration, and architecture checks so a structurally valid mutation cannot
silently create a logically worse target state. Identical mutations merge
without losing either evidence lens, and a deletion-only subset folds into one
unambiguous broader operation so the plan never tells an analyst to delete the
same object twice. Every run validates its complete accepted operation set, and
the compiler validates the complete merged set again, including consumer
coverage, final-name uniqueness, dependency cycles, exact mutation paths, and
cross-operation conflicts.

Package creation automatically splits large reviews into bounded, source-locked
shards inside their run-specific bundles and records evidence, authored-work,
and shard metrics under `review_work_units`. The current limits are more than 40
primary review items or, for Run 2, more than 120 authored behavior work units.
Current Run-2 shards contain source-hashed completion overlays; the full exact
evidence ledger remains in the adjacent bundle-local base review. The merge tool
refuses missing, duplicate, pending, changed-source, or incomplete work. Current
packages create no per-obligation micro-shards; legacy shards remain readable for
resumability. Each merge persists per-shard content-hash receipts, rechecks the
shards after assembly, and resumes from only the named failed shard. Drafts live
outside sealed inputs under `review-scratch`; accidental bundle scratch is moved
there without deletion. Architecture shards include a separate open-discovery
file for added `DISC-*` comparisons and the final all-object attestation.

## Inputs

The normal input is a complete GTM container export JSON. Source identity,
entity layers, IDs, and shapes are checked before any semantic scaffold is
built; ambiguous or unmodelled identity blocks all three reviews. Equivalent complete,
read-only GTM API or UI configuration evidence is also supported. Website,
business model, ecommerce, market, CMP, media, and server-routing context help
interpret the configuration.
Business inference uses only behavior reachable from active/configured roots.
Orphan logic remains an audit target but cannot redefine the business model,
and a server transport URL is not treated as proof of Google tag gateway.
Exported list-valued domains are normalized, while technical acronyms, generic
consent terms, and advertising labels cannot silently become market, CMP, or
publisher facts. Server-route hosts come only from explicit routing fields.

A web container can be reviewed for the browser-to-server routing visible in
its export. Transport tags do not need separate client-side blockers when the
web configuration demonstrably forwards the required consent state for
server-side enforcement. The audit checks that forwarding contract and keeps
the unseen server behavior outside its verdict. The receiving server container
requires its own complete export for a server-side audit.
Consent-like names/events and arbitrary blockers are only candidates; proof of
forwarding requires both a server route and a behavior-bearing payload chain.

An analyst may additionally provide an explicitly approved tracking plan in
JSON, CSV, XLSX, or XLSM format. It is preserved row by row as separately
labelled external requirement evidence and is available only to configuration
and architecture review. It never enters the container-only shared facts or
operational scan, and exact identifiers may be matched without inferring that a
similar name is an intended replacement.

## Outputs

- An audit summary and a validated canonical `cleanup_plan.xlsx`.
- A required analyst-facing `cleanup_plan.analyst.xlsx` when its separate
  evidence-locked AI editorial and post-gate transformation pass, with five lean human tabs followed by every canonical
  technical tab content-identical and hidden by default.
- A stakeholder Overview, exact atomic Actions first, grouped-but-lossless owner
  Decisions second, the complete Audit Register, and a full Custom HTML inventory
  without a separate traceability tab. A1 reconciles findings, operations,
  approval scope, maintenance versus behavior changes, simulator-confirmed
  activation, and remaining records. A5 uses seven analyst columns for execution
  context, role, technical health, replacement candidates, simplest safe target,
  and exact action/decision.
- The canonical workbook retains its two visible decision tabs and compact,
  unprotected proof tabs that analysts can unhide when needed.
- An operational synopsis with priority counts, owner decisions, clean scan
  modules, measurement-family target states, projected object deltas, and the
  next analyst action.
- A filterable general problem category before the exact area/problem type,
  with GTM layer prefixes retained in the affected-object column.
- Plain analyst-facing problem/change/readback wording, including explicit
  explanations for invisible Unicode reference corruption.
- Lossless hidden proof: long evidence continues onto another row instead of
  being silently truncated.
- Exact reconciled operations with preconditions, QA, and rollback.
- Fixed-point cleanup closure for dependencies made unused by planned actions,
  with separate approval and topological consumer-before-dependency ordering.
- A hash-locked row-level approval response in which every exact operation is
  approved, rejected, or amended before execution.
- Evidence-based priority dimensions, server/activation safety, and risk-based
  approval/decommission treatment. Runtime QA is out of scope; invoke
  `gtm-preview-recette` separately only when that work is requested.
- Every substantiated cleanup action in one exact operation set, plus genuine
  owner decisions and container-evidence limits with a recommended resolution.
- Exact duplicates become concrete canonical/remap/delete proposals; identical
  cross-run choices and upstream-reference repairs are shown once while all
  source judgments remain in the evidence ledger.
- One visible nonblocking evidence-boundary summary, with each exact per-object
  limit preserved in the hidden reviews instead of presented as a cleanup task.
- On request and after approval, direct GTM changes or a valid import JSON.
- A separate field-level change log after changes or an import artifact exist;
  an executed workbook is accepted only when the final complete readback exactly
  matches the approved simulation and every field change is linked.
- On request, an objective delta between two independently completed full audits:
  added/removed/changed objects and new/resolved/recurring findings, operations,
  decisions, and families. Previous verdicts are never carried into the new run.

The cleanup plan says what should change. The change log says what did change.
If the analyst-workbook transformation fails, the validated canonical workbook
remains the technical recovery record while analyst delivery is incomplete;
repair only the presentation step, with no audit scan rerun or weakening.

## What It Does Not Do

This skill does not run GTM Preview, Tag Assistant, browser/network, live CMP,
dataLayer, or vendor-platform QA. It does not make legal decisions, implement a
missing website/dataLayer contract, audit an unseen server container, mutate
without approval, or publish a GTM version.

## Install

Python 3.11+ provides deterministic scaffolds and gates. `openpyxl` creates XLSX
files; optional `esprima` adds JavaScript parser facts. If parser coverage is
unavailable or fails for a code block, the configuration review receives a
mandatory evidence-limit obligation and cannot silently treat empty AST facts
as a clean result.

```powershell
python -m pip install -e ".[analysis,dev]"
```

Use `gtm_skill_identity.py verify` when both a development source and installed
copy exist; version strings alone do not prove that the runnable trees match.
Every new task begins with one compact intake exchange that confirms the exact
container JSON/equivalent source and requested result. Then run
`gtm_skill_identity.py check`. Installed/bundled copies need a
matching declared release manifest; a clean Git checkout may prove the same
exact runtime identity from its tracked commit and file set.

The full audit requires the deterministic Python pipeline and complete
container evidence. If either is unavailable, report the audit as blocked and
request the missing prerequisite; there is no reduced audit mode.

## Start An Audit

First ask the analyst once to identify or confirm the exact complete source and
requested outcome; wait for the response. Infer safe remaining context after
that answer instead of silently selecting a download or starting a long
questionnaire.

```powershell
python -B scripts/gtm_skill_identity.py check --root . --pretty
python -B scripts/gtm_context_model.py container.json --pretty
python -B scripts/gtm_audit_package_build.py container.json --out-dir audit-package --pretty
```

Present the preflight's provided, high-confidence inferred, and unresolved
context. Pass known answers in a small JSON file with `--context
audit-context.json`. Unresolved business, naming, ownership, lifecycle, folder,
or preferred-target questions remain nonblocking owner decisions and stop only
their dependent mutation, not the three reviews or workbook. Add `--requirements
approved-plan.xlsx` only when the analyst explicitly approves that file as
requirement evidence.

Complete the three bundle-local review files independently in three fresh
contexts, validate and seal them, compile the exact cleanup operations, then
validate the complete audit-and-plan package:

```powershell
python -B scripts/gtm_review_isolation.py seal container.json audit-package operational_sanitation --context-id "<actual-run-1-context-id>" --pretty
python -B scripts/gtm_review_isolation.py seal container.json audit-package configuration_correctness --context-id "<actual-run-2-context-id>" --pretty
python -B scripts/gtm_review_isolation.py seal container.json audit-package business_architecture --context-id "<actual-run-3-context-id>" --pretty
python -B scripts/gtm_operation_compile.py container.json audit-package/operational_review.json audit-package/configuration_review.json audit-package/architecture_review.json reconciled_operations.json --route "Pending user selection" --pretty
python -B scripts/gtm_three_run_gate.py container.json audit-package --operations reconciled_operations.json --pretty
```

Use a distinct fresh reasoning context per run and never provide another run's
verdict artifact as input. Follow each run's `review_work_units` strategy. For a
sharded run, work inside its bundle, check every declared shard, merge it back
to the bundle-local review path, and then seal the complete validator-passing run.
If a sealed run needs correction, amend only that run from a fresh context with
`--amendment-of <current-seal-sha256>`; the prior review and seal remain archived.

The exact compilation, future-state, workbook, privacy, and change-log commands
are in `references/02-commands/validation-commands.md`. Before approved direct
mutation or applying an import artifact, `gtm_execution_guard.py` enforces exact
do-not-touch, server-route, activation, quarantine, source, and future-state
preconditions.

Create and validate the exact row-level approval surface before mutation:

```powershell
python -B scripts/gtm_approval_response.py template reconciled_operations.json approval_response.json --pretty
python -B scripts/gtm_approval_response.py validate reconciled_operations.json approval_response.json --pretty
python -B scripts/gtm_execution_guard.py reconciled_operations.json audit-package/context.json future_state_gate.json --source-export container.json --live-readback fresh-workspace-readback.json --approval-response approval_response.json --output execution_preflight.json --pretty
```

Compare two independently completed full audits without reusing old conclusions:

```powershell
python -B scripts/gtm_audit_delta.py previous-audit-package current-audit-package --output audit_delta.json --pretty
```

## Scalability Without Reduced Coverage

On a representative 319-row messy container, the v1.9 package retained 15,096
exact configuration evidence obligations and exposed 2,647 authored behavior
work units while reducing the generated artifact set from 2,092 files and about
606 MB in v1.8 to 69 files and about 352 MB. Per-obligation shards fell from
1,008 to zero. These metrics are regression gates for packaging cost; they do
not cap objects, evidence, findings, or any of the three independent scans.

## Repository Map

- `SKILL.md`: activation and execution instructions for agents.
- `references/01-skill/`: users, questions, inputs, outputs, acceptance, limits.
- `references/02-commands/`: runnable workflow commands.
- `references/03-rules/`: analyst and mutation rules.
- `scripts/`: source scans, three review engines, reconciliation, simulation,
  workbook, privacy, packaging, and validation tools.
- `tests/`: regression fixtures for common and subtle GTM failures.

## Release Checks

```powershell
python -m ruff check --no-cache .
python -B -m unittest discover -s tests -v
python -B scripts/gtm_self_test.py
python -B scripts/gtm_vendor_registry.py
python -B scripts/check_release.py --tag v1.13.0
git diff --check
```

Never commit client exports, generated audits, domains, IDs, credentials,
emails, screenshots, workbooks, or local paths. Release bundles are built with
`scripts/build_skill_package.py`.

Releases use `vMAJOR.MINOR.PATCH` semantic version tags. Pre-release and build
metadata suffixes are accepted when needed, for example `v1.1.0-rc.1` or
`v1.1.0+build.7`; the tag must match the normalized project version for a
versioned release check.

Licensed under the MIT License.
