# Changelog

## v17.3.0 (2026-10-19)

First public release of the greenfield rewrite. It replaces v2.2.1 entirely; there is no migration path from
v2.x audit packages.

### Workflow
- **Intake and prepare:**
  - intake questions each name the context field they fill;
  - optional tracking plan (CSV, XLSX, JSON or text);
  - protected objects;
  - approved Advanced Consent Mode destinations and server hosts;
  - the source export is locked by hash.
- **Rule catalog:** a deterministic catalog writes candidates; every candidate is confirmed in a finding or dismissed with a reason.
- **Review:** five domain reviewers run in parallel, with D5 starting from a candidate-blind family pass; then an integrator and a fresh verifier.
- **Packs:** evidence packs list each variable's value source once.

### Engine
- **Simulation:** checks references, names, write ownership by field or row identity, protected objects and loss of consent controls.
- **Per-operation applicability** with exactly the declared prerequisites:
  - consent predicates for new vendor collection paths;
  - readiness never above prerequisites or above values whose meaning is still open (shared settings and exact aliases are not new values);
  - a ready finding never above its operations;
  - warnings for settings that tags stop sending.
- **Effective settings:** one definition of what a tag sends, across Google tag, settings variable and own rows.
- **Execution trace:** every action in the state it applies to, through the same mutation code as the simulation.
- **Verdict history:** read one way by `check` and `finalize`.
- **Reader texts:** must cite objects by key and use GTM terms; record IDs, area codes, paths and raw export fields are rejected.
- **Masking:** applies to every view and workbook, including scalar values identified by their path.

### Workbook
- **Five tabs:** Summary, Findings and actions, Questions, Custom code, Inventory, in English or French.
- **GTM interface steps:**
  - generated from the execution trace, in dependency order, marked "after change n";
  - family changes grouped only when the order cannot change the result;
  - code rows per action, with a stable reference.
- **Saved-file verification:** cells against the layout, code against a fresh trace, prerequisite order, literal text and masking.

### Validation
Five real containers, judged against frozen keys and cleaned comparators:
- 0 structurally unsafe ready changes;
- quality within about one point of the strongest earlier baselines on four containers;
- about $5–11 and 25–55 minutes per container.

The final fixes were proven by replaying 12 preserved runs and by 46 automated tests.

## v2.2.1 and earlier

See the [v2.2.1 release](https://github.com/haiqigeng/4-gtm-container-audit-cleanup/releases/tag/v2.2.1) and the
`v1.x`–`v2.2.1` tags.
