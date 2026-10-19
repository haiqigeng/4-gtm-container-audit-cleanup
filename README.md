# GTM Container Audit & Optimize

[![Validate skill](https://github.com/haiqigeng/4-gtm-container-audit-cleanup/actions/workflows/ci.yml/badge.svg)](https://github.com/haiqigeng/4-gtm-container-audit-cleanup/actions/workflows/ci.yml)

An agent skill that audits one complete Google Tag Manager **web-container** export the way a senior web analyst
would: what is wrong, what can be simpler, and what should stay. Each justified change becomes an exact
operation, and the resulting container is validated statically. The deliverable is one analyst workbook, in
English or French.

**Current release:** [v17.3.0](https://github.com/haiqigeng/4-gtm-container-audit-cleanup/releases/tag/v17.3.0), for
analyst-supervised field use. The skill never changes GTM: an analyst reviews every proposed change and applies it.

## North Star

Judge the container as if a senior web analyst rebuilt it today, from an empty container, for the same proven
needs. Report defects, materially simpler designs, designs that should stay, owner decisions and evidence limits.
Then deliver exact, statically validated changes in one workbook a junior analyst can act on.

## What it audits

Five domain reviewers cover areas A02–A26:

| Domain | Areas |
| --- | --- |
| D1 Consent, privacy and security | CMP and consent infrastructure, direct consent architecture, Advanced Consent Mode, client-to-server transport, server handoff boundary, personal data and secrets |
| D2 Google measurement | Google settings ownership, destinations and page views, GA4 events and parameters, ecommerce, Google Ads and Floodlight, value semantics |
| D3 Vendors, templates and custom code | Tag and template configuration, non-Google vendors, custom templates, Custom HTML and JavaScript |
| D4 Structure and maintainability | Inventory, references, lifecycle and usage, trigger conditions, firing options and sequencing, variables, environments, naming and folders |
| D5 Families, duplicates and target design | Duplicates and near-duplicates, efficiency, target architecture (drafted for the integrator) |

Key positions:
- direct vendor tags use a consent-free business trigger plus one reusable, fail-closed denial blocker;
- Advanced Consent Mode and server-side consent ownership apply only where the owner approves them;
- data that leaves the container is removed or renamed only when the source shows it is broken or unused, or the owner approves.

Server containers, runtime QA, tracking-plan design and legal rulings are out of scope.

## How it works

```text
intake            owner questions (completeness, language, tracking plan, protected objects, consent approvals)
prepare           lock the export, run the deterministic rule catalog, write evidence packs
D1–D5             five reviewers in parallel (D5 starts with a candidate-blind family pass)
integrate         merge overlaps, resolve conflicts, apply the naming convention, write the summary
verify            a fresh verifier checks every ready/conditional change and every Critical/High finding
build             finalize, simulate the whole target, write and verify the workbook
```

The engine checks every operation with exactly its declared prerequisites:
- references, names, conflicting writes, protected objects and consent controls;
- new vendor collection paths without a consent predicate;
- readiness against prerequisites and against values whose meaning is still open.

It also lists settings that tags would stop sending. Agents resolve these errors during the run.

## The workbook

| Tab | Job |
| --- | --- |
| 1 Summary | Scope and limits, findings by priority and type, target architecture, naming, how to use the file |
| 2 Findings and actions | One row per finding: what is wrong, why it matters, what to do as GTM interface steps in execution order, status, check and undo, and a decision column |
| 3 Questions | Each open question once, with the problems it blocks, ready to send to the site owner |
| 4 Custom code | Current and new code for every code change, each row with a stable reference |
| 5 Inventory | Every object with its outcome: keep, change, remove, rename or create |

`final.json` stays as the exact machine-readable copy. `build` reopens the saved workbook and verifies it:
- every cell matches the computed layout;
- every code row matches the engine's execution trace;
- no change is listed before its prerequisite;
- text is literal and private values are masked.

## Requirements

- Python 3.11+ and [`openpyxl`](https://openpyxl.readthedocs.io/) 3.1+
- Optional: `esprima` 4.0.1 for JavaScript syntax checks
- A host that runs sub-agents in parallel, such as Codex or Claude Code; with a cap on active agents, workers start as slots free up

## Quick start

Load the skill and ask the agent to audit an export. It follows [`SKILL.md`](SKILL.md):

> Use the gtm-container-audit-optimize skill to audit `<export.json>`. Output directory `<OUT>`. Deliver the
> verified workbook.

The agent drives the command line in `scripts/gtm.py`:

| Command | Use |
| --- | --- |
| `intake SOURCE [--context FILE]` | Material questions for the owner |
| `prepare SOURCE --context FILE --out OUT [--plan PLAN]` | Lock the source, run rules, write packs (a tracking plan is optional) |
| `show OUT KEY [KEY ...]` / `siblings OUT KEY` | Read an object, or the objects sharing its pattern |
| `add OUT --worker W --file F` | Validate and save records |
| `list OUT` / `status OUT` | Record listing and progress |
| `check OUT --worker W` | Validate one worker's work, including a simulation of its operations |
| `finalize OUT` | Merge records under integrator decisions, simulate the target, write `final.json` |
| `build OUT` | Write `OUT/gtm-container-audit.xlsx` and verify it |

## Using it in the field

1. Read tab 2 from the top, and decide each row: Apply, Reject or Later.
2. Send tab 3 to the site owner. Rows marked "Needs answer" wait for those answers.
3. Apply approved changes **in a new GTM workspace**, following each row's changes in order. Then run the row's checks in **Preview** before publishing.

## Validation behind v17.3.0

| Gate | Result on five real containers |
| --- | --- |
| Structural safety (ready changes of a kind the engine checks) | 0 unsafe on every container |
| Quality against the strongest earlier baselines | Within about one point on four containers; one container 0.33 below its previous run |
| Findings beyond the deterministic detectors | 38–51%, almost all supported by independent review |
| Workbook utility | 7–7.5 / 8 |
| Cost and time per container | about $5–11 and 25–55 minutes; earlier versions took $15–34 and 55–114 minutes |

The final deterministic fixes were proven without model runs:
- 12 preserved real runs replay to identical findings and operations, and every workbook verifies;
- the known safety catches still fire;
- no credential literal appears in any workbook;
- 46 automated tests and a clean-install smoke test pass in English and French.

## Known limits

- Reviewer judgment varies between runs: producer details can be missed, and assumptions about receiving systems can be wrong. The analyst's review and Preview are part of the workflow for this reason.
- Questions are occasionally indirect, and long change cells are dense.
- The skill has not yet been tested on a container outside its development exports. The tracking-plan input has not been exercised in a model run.
- The audit is static. It doesn't certify live firing, consent timing, what vendors receive, or legal compliance.

## Repository layout

```text
SKILL.md                     coordinator workflow, worker procedure, commands, completion
references/
  policy.md                  classes, readiness, priority, change and removal rules, consent policy, evidence, writing
  records.md                 record shapes, actions and path grammar, what `check` reports
  integrator.md, verifier.md, naming.md
  domains/d1…d5              each reviewer's areas, checklist and typical operations
scripts/
  gtm.py                     command line
  gtmaudit/source.py         export model, graph, consent evidence, effective settings
  gtmaudit/rules/            deterministic candidate catalog (one module per domain)
  gtmaudit/render.py, packs.py, privacy.py    evidence views and masking
  gtmaudit/records.py        record contract and validation
  gtmaudit/paths.py          action path grammar
  gtmaudit/operations.py     applying changes: simulation and execution trace
  gtmaudit/checks.py         judging changes: applicability, consent routes, payloads
  gtmaudit/final.py          live projection, readiness, verdict history, finalize
  gtmaudit/steps.py          GTM interface wording (English and French)
  gtmaudit/workbook.py       five-tab workbook and saved-file verification
tests/                       behavioural tests by module and an end-to-end CLI test
agents/openai.yaml           agent metadata
```

## Development

```bash
python -m pip install "openpyxl>=3.1" "pytest>=8" "ruff==0.15.22"
python -m ruff check --no-cache .
python -B -m pytest -q -p no:cacheprovider
```

The project follows [`AGENTS.md`](AGENTS.md): no compatibility layers, the simplest complete implementation, one
home per concern, and positive invariants enforced by checks.

## Versioning

v17.3.0 is a greenfield rewrite. It replaces the v2.x line entirely: workflow, record contract, commands and
workbook all changed. Versions 3 to 16 were internal development builds and were never published. See
[CHANGELOG.md](CHANGELOG.md). Earlier releases remain available as tags `v1.x`–`v2.2.1`.

## License

[MIT](LICENSE)
